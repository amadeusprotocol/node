//! Minimal canonical RLP: decode borrowed items, encode the few shapes we hash.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    NonCanonical,
    TrailingBytes,
    Expected(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub struct Item<'a> {
    /// the whole encoding of this item (prefix included)
    pub raw: &'a [u8],
    pub payload: &'a [u8],
    pub is_list: bool,
}

fn be_len(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.is_empty() || bytes[0] == 0 || bytes.len() > 8 {
        return Err(Error::NonCanonical);
    }
    Ok(bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize))
}

/// one item from the front of `buf`, returns it and the rest
pub fn decode(buf: &[u8]) -> Result<(Item<'_>, &[u8]), Error> {
    let p = *buf.first().ok_or(Error::Truncated)?;
    let (header, len, is_list) = match p {
        0x00..=0x7f => (0, 1, false),
        0x80..=0xb7 => (1, (p - 0x80) as usize, false),
        0xb8..=0xbf => {
            let n = (p - 0xb7) as usize;
            let len = be_len(buf.get(1..1 + n).ok_or(Error::Truncated)?)?;
            if len < 56 { return Err(Error::NonCanonical); }
            (1 + n, len, false)
        }
        0xc0..=0xf7 => (1, (p - 0xc0) as usize, true),
        0xf8..=0xff => {
            let n = (p - 0xf7) as usize;
            let len = be_len(buf.get(1..1 + n).ok_or(Error::Truncated)?)?;
            if len < 56 { return Err(Error::NonCanonical); }
            (1 + n, len, true)
        }
    };
    let end = header.checked_add(len).ok_or(Error::Truncated)?;
    if buf.len() < end { return Err(Error::Truncated); }
    let payload = if p < 0x80 { &buf[0..1] } else { &buf[header..end] };
    //a single byte below 0x80 must be encoded as itself
    if p == 0x81 && payload[0] < 0x80 { return Err(Error::NonCanonical); }
    Ok((Item { raw: &buf[..end], payload, is_list }, &buf[end..]))
}

/// exactly one item and nothing after it
pub fn decode_exact(buf: &[u8]) -> Result<Item<'_>, Error> {
    let (item, rest) = decode(buf)?;
    if !rest.is_empty() { return Err(Error::TrailingBytes); }
    Ok(item)
}

impl<'a> Item<'a> {
    pub fn list(&self) -> Result<Vec<Item<'a>>, Error> {
        if !self.is_list { return Err(Error::Expected("list")); }
        let mut items = Vec::new();
        let mut rest = self.payload;
        while !rest.is_empty() {
            let (item, r) = decode(rest)?;
            items.push(item);
            rest = r;
        }
        Ok(items)
    }

    pub fn bytes(&self) -> Result<&'a [u8], Error> {
        if self.is_list { return Err(Error::Expected("bytes")); }
        Ok(self.payload)
    }

    pub fn bytes32(&self) -> Result<[u8; 32], Error> {
        self.bytes()?.try_into().map_err(|_| Error::Expected("32 bytes"))
    }

    pub fn u64(&self) -> Result<u64, Error> {
        let b = self.bytes()?;
        if b.len() > 8 { return Err(Error::Expected("u64")); }
        if b.first() == Some(&0) { return Err(Error::NonCanonical); }
        Ok(b.iter().fold(0u64, |acc, x| (acc << 8) | *x as u64))
    }
}

pub fn encode_bytes(out: &mut Vec<u8>, b: &[u8]) {
    match b.len() {
        1 if b[0] < 0x80 => out.push(b[0]),
        n if n < 56 => { out.push(0x80 + n as u8); out.extend_from_slice(b); }
        n => { let l = be_bytes(n as u64); out.push(0xb7 + l.len() as u8); out.extend_from_slice(&l); out.extend_from_slice(b); }
    }
}

pub fn encode_u64(out: &mut Vec<u8>, v: u64) {
    encode_bytes(out, &be_bytes(v));
}

pub fn encode_list(out: &mut Vec<u8>, payload: &[u8]) {
    match payload.len() {
        n if n < 56 => out.push(0xc0 + n as u8),
        n => { let l = be_bytes(n as u64); out.push(0xf7 + l.len() as u8); out.extend_from_slice(&l); }
    }
    out.extend_from_slice(payload);
}

fn be_bytes(v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    b[b.iter().position(|x| *x != 0).unwrap_or(8)..].to_vec()
}
