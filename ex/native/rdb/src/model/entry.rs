use crate::model::_codec as codec;
use crate::model::_codec::{DecodeFromTerm, EncodeToTerm};
use crate::model::tx::TXU;
use vecpak::Term;

#[derive(Debug, Clone)]
pub struct Header {
    pub prev_hash: Vec<u8>,
    pub height: u64,
    pub slot: u64,
    pub prev_slot: u64,
    pub signer: Vec<u8>,
    pub dr: Vec<u8>,
    pub vr: Vec<u8>,
    pub root_tx: Vec<u8>,
    pub root_validator: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub header: Header,
    pub txs: Vec<TXU>,
    pub mask: Option<Vec<u8>>,
    pub mask_size: Option<i128>,
    pub mask_set_size: Option<i128>,
}

impl EncodeToTerm for Header {
    fn to_term(&self) -> Result<Term, &'static str> {
        Ok(Term::PropList(vec![
            (
                Term::Binary(b"prev_hash".to_vec()),
                Term::Binary(self.prev_hash.clone()),
            ),
            (
                Term::Binary(b"height".to_vec()),
                Term::VarInt(self.height as i128),
            ),
            (
                Term::Binary(b"slot".to_vec()),
                Term::VarInt(self.slot as i128),
            ),
            (
                Term::Binary(b"prev_slot".to_vec()),
                Term::VarInt(self.prev_slot as i128),
            ),
            (
                Term::Binary(b"signer".to_vec()),
                Term::Binary(self.signer.clone()),
            ),
            (Term::Binary(b"dr".to_vec()), Term::Binary(self.dr.clone())),
            (Term::Binary(b"vr".to_vec()), Term::Binary(self.vr.clone())),
            (
                Term::Binary(b"root_tx".to_vec()),
                Term::Binary(self.root_tx.clone()),
            ),
            (
                Term::Binary(b"root_validator".to_vec()),
                Term::Binary(self.root_validator.clone()),
            ),
        ]))
    }
}

impl DecodeFromTerm for Header {
    fn from_term(t: &Term) -> Self {
        let Term::PropList(pairs) = t else {
            unreachable!("Expected PropList for Header")
        };

        Header {
            prev_hash: codec::pl_get_bytes(pairs, b"prev_hash").to_vec(),
            height: codec::pl_get_varint(pairs, b"height") as u64,
            slot: codec::pl_get_varint(pairs, b"slot") as u64,
            prev_slot: codec::pl_get_varint(pairs, b"prev_slot") as u64,
            signer: codec::pl_get_bytes(pairs, b"signer").to_vec(),
            dr: codec::pl_get_bytes(pairs, b"dr").to_vec(),
            vr: codec::pl_get_bytes(pairs, b"vr").to_vec(),
            root_tx: codec::pl_get_bytes(pairs, b"root_tx").to_vec(),
            root_validator: codec::pl_get_bytes(pairs, b"root_validator").to_vec(),
        }
    }
}

impl EncodeToTerm for Entry {
    fn to_term(&self) -> Result<Term, &'static str> {
        let mut txs_list = Vec::with_capacity(self.txs.len());
        for tx in &self.txs {
            txs_list.push(tx.to_term()?);
        }

        let mut pairs = vec![
            (
                Term::Binary(b"hash".to_vec()),
                Term::Binary(self.hash.clone()),
            ),
            (
                Term::Binary(b"signature".to_vec()),
                Term::Binary(self.signature.clone()),
            ),
            (Term::Binary(b"header".to_vec()), self.header.to_term()?),
            (Term::Binary(b"txs".to_vec()), Term::List(txs_list)),
        ];

        if let Some(ref m) = self.mask {
            pairs.push((Term::Binary(b"mask".to_vec()), Term::Binary(m.clone())));
        }
        if let Some(ms) = self.mask_size {
            pairs.push((Term::Binary(b"mask_size".to_vec()), Term::VarInt(ms)));
        }
        if let Some(mss) = self.mask_set_size {
            pairs.push((Term::Binary(b"mask_set_size".to_vec()), Term::VarInt(mss)));
        }

        Ok(Term::PropList(pairs))
    }
}

impl DecodeFromTerm for Entry {
    fn from_term(t: &Term) -> Self {
        let Term::PropList(pairs) = t else {
            unreachable!("Expected PropList for Entry")
        };

        let hash = codec::pl_get_bytes(pairs, b"hash").to_vec();
        let signature = codec::pl_get_bytes(pairs, b"signature").to_vec();

        let header_term = codec::pl_find(pairs, b"header");
        let header = Header::from_term(header_term);

        let txs_term_list = codec::pl_get_list(pairs, b"txs");
        let txs = txs_term_list.iter().map(|t| TXU::from_term(t)).collect();

        let mask = codec::pl_get_bytes_opt(pairs, b"mask").map(|b| b.to_vec());

        let mask_size = codec::pl_get_varint_opt(pairs, b"mask_size");
        let mask_set_size = codec::pl_get_varint_opt(pairs, b"mask_set_size");

        Entry {
            hash,
            signature,
            header,
            txs,
            mask,
            mask_size,
            mask_set_size,
        }
    }
}

pub fn from_bytes(data: &[u8]) -> Result<Entry, &'static str> {
    let term = vecpak::decode(data)?;
    Ok(Entry::from_term(&term))
}
