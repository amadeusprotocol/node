//! Parlia block headers: hash, the fields the bridge needs, and extraData contents.
//! Layout after Luban/Bohr (bsc consensus/parlia): vanity(32) | on epoch blocks:
//! count(1) + count * (address(20) + bls vote key(48)) + turnLength(1) | rlp(VoteAttestation)? | seal(65)

use super::keccak256;
use super::rlp;

pub const EXTRA_VANITY: usize = 32;
pub const EXTRA_SEAL: usize = 65;
pub const VALIDATOR_BYTES: usize = 20 + 48;
/// Maxwell epoch length
pub const EPOCH_LENGTH: u64 = 1000;
/// types.MaxAttestationExtraLength
pub const MAX_ATTESTATION_EXTRA: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Rlp(rlp::Error),
    BadHeader,
    BadExtra,
    NotEpochBlock,
    BadAttestation,
}

impl From<rlp::Error> for Error {
    fn from(e: rlp::Error) -> Self { Error::Rlp(e) }
}

pub struct Header<'a> {
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub number: u64,
    pub time: u64,
    pub extra: &'a [u8],
}

/// Fields are read by position, so fields appended by later BSC hard forks only change the hash.
pub fn parse(raw: &[u8]) -> Result<Header<'_>, Error> {
    let f = rlp::decode_exact(raw)?.list()?;
    if f.len() < 15 { return Err(Error::BadHeader); }
    Ok(Header {
        hash: keccak256(raw),
        parent_hash: f[0].bytes32()?,
        state_root: f[3].bytes32()?,
        number: f[8].u64()?,
        time: f[11].u64()?,
        extra: f[12].bytes()?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validator {
    pub address: [u8; 20],
    pub vote_key: [u8; 48],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteData {
    pub source_number: u64,
    pub source_hash: [u8; 32],
    pub target_number: u64,
    pub target_hash: [u8; 32],
}

impl VoteData {
    /// what validators sign: keccak(rlp([source_number, source_hash, target_number, target_hash]))
    pub fn hash(&self) -> [u8; 32] {
        let mut p = Vec::with_capacity(84);
        rlp::encode_u64(&mut p, self.source_number);
        rlp::encode_bytes(&mut p, &self.source_hash);
        rlp::encode_u64(&mut p, self.target_number);
        rlp::encode_bytes(&mut p, &self.target_hash);
        let mut out = Vec::with_capacity(86);
        rlp::encode_list(&mut out, &p);
        keccak256(&out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// bit i = i-th validator of the set sorted by address
    pub vote_set: u64,
    pub agg_sig: [u8; 96],
    pub data: VoteData,
}

fn body<'a>(h: &Header<'a>) -> Result<&'a [u8], Error> {
    if h.extra.len() < EXTRA_VANITY + EXTRA_SEAL { return Err(Error::BadExtra); }
    Ok(&h.extra[EXTRA_VANITY..h.extra.len() - EXTRA_SEAL])
}

/// (validators in header order, turn length, bytes after them) of an epoch block
fn epoch_section<'a>(h: &Header<'a>) -> Result<(Vec<Validator>, u8, &'a [u8]), Error> {
    if h.number % EPOCH_LENGTH != 0 { return Err(Error::NotEpochBlock); }
    let body = body(h)?;
    let n = *body.first().ok_or(Error::BadExtra)? as usize;
    let end = 1 + n * VALIDATOR_BYTES;
    if n == 0 || body.len() < end + 1 { return Err(Error::BadExtra); }
    let validators = body[1..end].chunks_exact(VALIDATOR_BYTES)
        .map(|c| Validator { address: c[..20].try_into().unwrap(), vote_key: c[20..].try_into().unwrap() })
        .collect();
    Ok((validators, body[end], &body[end + 1..]))
}

/// validator set and turn length announced by an epoch block
pub fn epoch_validators(h: &Header) -> Result<(Vec<Validator>, u8), Error> {
    let (validators, turn_length, _) = epoch_section(h)?;
    Ok((validators, turn_length))
}

/// the fast-finality vote attestation a header carries, if any
pub fn attestation(h: &Header) -> Result<Option<Attestation>, Error> {
    let bytes = if h.number % EPOCH_LENGTH == 0 { epoch_section(h)?.2 } else { body(h)? };
    if bytes.is_empty() { return Ok(None); }
    let f = rlp::decode_exact(bytes)?.list()?;
    if f.len() != 4 { return Err(Error::BadAttestation); }
    let d = f[2].list()?;
    if d.len() != 4 || f[3].bytes()?.len() > MAX_ATTESTATION_EXTRA { return Err(Error::BadAttestation); }
    Ok(Some(Attestation {
        vote_set: f[0].u64()?,
        agg_sig: f[1].bytes()?.try_into().map_err(|_| Error::BadAttestation)?,
        data: VoteData { source_number: d[0].u64()?, source_hash: d[1].bytes32()?, target_number: d[2].u64()?, target_hash: d[3].bytes32()? },
    }))
}
