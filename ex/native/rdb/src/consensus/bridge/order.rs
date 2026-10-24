//! Bridge order: one packed byte layout on every chain, so remote contracts only slice
//! and hash bytes. Integers big-endian; variable fields as u16 BE length + bytes;
//! chains are names zero-padded to 32 bytes (lowercase a-z 0-9 - _).
//!
//! version u8 | src_chain [32] | nonce u64 | sender | refund_to | src_coin | amount u128 |
//! dst_chain [32] | dst_coin | recipient | output_amount u128 | fill_deadline u64 |
//! exclusive_filler | exclusivity_deadline u64 | message | gas_drop u128 | gas_drop_fee u128
//!
//! Delivery: an order with gas_drop_fee = 0 is claimed by its recipient. Otherwise whoever
//! delivers it gets gas_drop_fee (in the destination coin, out of the order) and must hand
//! the recipient gas_drop of the destination chain's native gas coin with the claim.
//! output_amount = amount - bridge fee (charged on Amadeus sends only) - gas_drop_fee.

pub const VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Order {
    pub src_chain: [u8; 32],
    pub nonce: u64,
    pub sender: Vec<u8>,
    pub refund_to: Vec<u8>,
    pub src_coin: Vec<u8>,
    pub amount: u128,
    pub dst_chain: [u8; 32],
    pub dst_coin: Vec<u8>,
    pub recipient: Vec<u8>,
    pub output_amount: u128,
    pub fill_deadline: u64,
    pub exclusive_filler: Vec<u8>,
    pub exclusivity_deadline: u64,
    pub message: Vec<u8>,
    pub gas_drop: u128,
    pub gas_drop_fee: u128,
}

/// a chain name as its 32-byte field, None unless it is 1..32 bytes of a-z 0-9 - _
pub fn chain_name(name: &[u8]) -> Option<[u8; 32]> {
    let ok = !name.is_empty() && name.len() <= 32 && name.iter().all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'));
    ok.then(|| {
        let mut out = [0u8; 32];
        out[..name.len()].copy_from_slice(name);
        out
    })
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(u16::try_from(b.len()).expect("order_field_too_long")).to_be_bytes());
    out.extend_from_slice(b);
}

impl Order {
    pub fn pack(&self) -> Vec<u8> {
        let mut o = vec![VERSION];
        o.extend_from_slice(&self.src_chain);
        o.extend_from_slice(&self.nonce.to_be_bytes());
        put_bytes(&mut o, &self.sender);
        put_bytes(&mut o, &self.refund_to);
        put_bytes(&mut o, &self.src_coin);
        o.extend_from_slice(&self.amount.to_be_bytes());
        o.extend_from_slice(&self.dst_chain);
        put_bytes(&mut o, &self.dst_coin);
        put_bytes(&mut o, &self.recipient);
        o.extend_from_slice(&self.output_amount.to_be_bytes());
        o.extend_from_slice(&self.fill_deadline.to_be_bytes());
        put_bytes(&mut o, &self.exclusive_filler);
        o.extend_from_slice(&self.exclusivity_deadline.to_be_bytes());
        put_bytes(&mut o, &self.message);
        o.extend_from_slice(&self.gas_drop.to_be_bytes());
        o.extend_from_slice(&self.gas_drop_fee.to_be_bytes());
        o
    }

    pub fn unpack(b: &[u8]) -> Option<Order> {
        let mut r = Reader(b);
        if r.take(1)? != [VERSION] { return None; }
        let order = Order {
            src_chain: r.fixed()?,
            nonce: u64::from_be_bytes(r.fixed()?),
            sender: r.bytes()?,
            refund_to: r.bytes()?,
            src_coin: r.bytes()?,
            amount: u128::from_be_bytes(r.fixed()?),
            dst_chain: r.fixed()?,
            dst_coin: r.bytes()?,
            recipient: r.bytes()?,
            output_amount: u128::from_be_bytes(r.fixed()?),
            fill_deadline: u64::from_be_bytes(r.fixed()?),
            exclusive_filler: r.bytes()?,
            exclusivity_deadline: u64::from_be_bytes(r.fixed()?),
            message: r.bytes()?,
            gas_drop: u128::from_be_bytes(r.fixed()?),
            gas_drop_fee: u128::from_be_bytes(r.fixed()?),
        };
        r.0.is_empty().then_some(order)
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n { return None; }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
    fn bytes(&mut self) -> Option<Vec<u8>> {
        let len = u16::from_be_bytes(self.fixed()?) as usize;
        Some(self.take(len)?.to_vec())
    }
}
