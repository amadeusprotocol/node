use alloc::vec::Vec;

const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub enum Term {
    Nil,
    Bool(bool),
    Int(i128),
    Binary(Vec<u8>),
    List(Vec<Term>),
    Map(Vec<(Term, Term)>),
}

fn encode_varint(buf: &mut Vec<u8>, v: i128) {
    if v == 0 {
        buf.push(0);
        return;
    }
    let mag = v.unsigned_abs();
    let first = mag.leading_zeros() as usize / 8;
    buf.push(((v < 0) as u8) << 7 | (16 - first) as u8);
    buf.extend_from_slice(&mag.to_be_bytes()[first..]);
}

fn encode_into(buf: &mut Vec<u8>, term: &Term, depth: usize) -> Result<(), &'static str> {
    if depth > MAX_DEPTH {
        return Err("too_deep");
    }
    match term {
        Term::Nil => buf.push(0),
        Term::Bool(true) => buf.push(1),
        Term::Bool(false) => buf.push(2),
        Term::Int(v) => {
            buf.push(3);
            encode_varint(buf, *v);
        }
        Term::Binary(b) => {
            buf.push(5);
            encode_varint(buf, b.len() as i128);
            buf.extend_from_slice(b);
        }
        Term::List(items) => {
            buf.push(6);
            encode_varint(buf, items.len() as i128);
            for it in items {
                encode_into(buf, it, depth + 1)?;
            }
        }
        Term::Map(pairs) => {
            buf.push(7);
            encode_varint(buf, pairs.len() as i128);
            let mut keyed: Vec<(Vec<u8>, &Term)> = Vec::with_capacity(pairs.len());
            for (k, v) in pairs {
                let mut kb = Vec::new();
                encode_into(&mut kb, k, depth + 1)?;
                keyed.push((kb, v));
            }
            keyed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err("duplicate_map_key");
            }
            for (kb, v) in keyed {
                buf.extend_from_slice(&kb);
                encode_into(buf, v, depth + 1)?;
            }
        }
    }
    Ok(())
}

pub fn encode(term: &Term) -> Result<Vec<u8>, &'static str> {
    let mut buf = Vec::new();
    encode_into(&mut buf, term, 0)?;
    Ok(buf)
}

fn byte(buf: &[u8], i: &mut usize) -> Result<u8, &'static str> {
    let b = *buf.get(*i).ok_or("eof")?;
    *i += 1;
    Ok(b)
}

fn varint(buf: &[u8], i: &mut usize) -> Result<i128, &'static str> {
    let b0 = byte(buf, i)?;
    if b0 == 0 {
        return Ok(0);
    }
    if b0 == 0x80 {
        return Err("noncanonical_zero");
    }
    let len = (b0 & 0x7f) as usize;
    if len > 16 || buf.len().saturating_sub(*i) < len {
        return Err("varint");
    }
    if buf[*i] == 0 {
        return Err("varint_leading_zero");
    }
    let mut be = [0u8; 16];
    be[16 - len..].copy_from_slice(&buf[*i..*i + len]);
    *i += len;
    let m = u128::from_be_bytes(be);
    if b0 & 0x80 != 0 {
        if m > i128::MAX as u128 + 1 {
            return Err("varint_too_large");
        }
        Ok((m as i128).wrapping_neg())
    } else if m > i128::MAX as u128 {
        Err("varint_too_large")
    } else {
        Ok(m as i128)
    }
}

fn length(buf: &[u8], i: &mut usize) -> Result<usize, &'static str> {
    let n = varint(buf, i)?;
    if n < 0 || n as u128 > buf.len() as u128 {
        return Err("bad_length");
    }
    Ok(n as usize)
}

fn decode_at(buf: &[u8], i: &mut usize, depth: usize) -> Result<Term, &'static str> {
    if depth > MAX_DEPTH {
        return Err("too_deep");
    }
    Ok(match byte(buf, i)? {
        0 => Term::Nil,
        1 => Term::Bool(true),
        2 => Term::Bool(false),
        3 => Term::Int(varint(buf, i)?),
        5 => {
            let n = length(buf, i)?;
            if buf.len() - *i < n {
                return Err("eof");
            }
            let b = buf[*i..*i + n].to_vec();
            *i += n;
            Term::Binary(b)
        }
        6 => {
            let n = length(buf, i)?;
            let mut items = Vec::with_capacity(n.min(buf.len() - *i));
            for _ in 0..n {
                items.push(decode_at(buf, i, depth + 1)?);
            }
            Term::List(items)
        }
        7 => {
            let n = length(buf, i)?;
            let mut pairs = Vec::with_capacity(n.min(buf.len() - *i));
            let mut prev: Option<(usize, usize)> = None;
            for _ in 0..n {
                let start = *i;
                let k = decode_at(buf, i, depth + 1)?;
                if let Some((ps, pe)) = prev {
                    if buf[start..*i] <= buf[ps..pe] {
                        return Err("map_not_canonical");
                    }
                }
                prev = Some((start, *i));
                let v = decode_at(buf, i, depth + 1)?;
                pairs.push((k, v));
            }
            Term::Map(pairs)
        }
        _ => return Err("unknown_tag"),
    })
}

pub fn decode(buf: &[u8]) -> Result<Term, &'static str> {
    let mut i = 0;
    let t = decode_at(buf, &mut i, 0)?;
    if i != buf.len() {
        return Err("trailing_bytes");
    }
    Ok(t)
}

impl Term {
    pub fn get(&self, key: &[u8]) -> Option<&Term> {
        match self {
            Term::Map(pairs) => pairs.iter().find(|(k, _)| matches!(k, Term::Binary(b) if b == key)).map(|(_, v)| v),
            _ => None,
        }
    }
}
