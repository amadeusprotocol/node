//! Parlia fast finality (BEP-126), as bsc verifyVoteAttestation checks it.
//! An attestation is >= 2/3 of the validators signing VoteData{source, target}; when the
//! target is the source's direct child, both are justified and the source is final.

use super::header::{Attestation, Header, Validator};
use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;

/// prysm BLS (Ethereum consensus layer) signature domain, used for BSC votes
pub const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadVoteKey,
    SourceNotBelowTarget,
    TooManyVotes,
    NotEnoughVotes,
    BadSignature,
    BrokenAncestry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    /// sorted by address: vote bits index this order
    pub validators: Vec<Validator>,
    pub turn_length: u8,
}

impl ValidatorSet {
    /// vote keys are subgroup-checked here, once, so verifying a vote only decompresses them
    pub fn new(mut validators: Vec<Validator>, turn_length: u8) -> Result<Self, Error> {
        if validators.iter().any(|v| PublicKey::key_validate(&v.vote_key).is_err()) { return Err(Error::BadVoteKey); }
        validators.sort_by(|a, b| a.address.cmp(&b.address));
        Ok(Self { validators, turn_length })
    }

    pub fn quorum(&self) -> usize {
        (self.validators.len() * 2).div_ceil(3)
    }

    /// blocks after its epoch block a newly announced set takes over from this one (minerHistoryCheckLen)
    pub fn switch_offset(&self) -> u64 {
        (self.validators.len() as u64 / 2 + 1) * self.turn_length as u64 - 1
    }
}

/// The set that must sign an attestation for `target`: the snapshot at target-1 switched to the
/// set announced at `epoch_number` once (target-1) % epoch == old.switch_offset().
pub fn uses_announced_set(target: u64, epoch_number: u64, old: &ValidatorSet) -> bool {
    target - 1 >= epoch_number + old.switch_offset()
}

pub fn verify_attestation(att: &Attestation, set: &ValidatorSet) -> Result<(), Error> {
    if att.data.source_number >= att.data.target_number { return Err(Error::SourceNotBelowTarget); }
    if att.vote_set.count_ones() as usize > set.validators.len() { return Err(Error::TooManyVotes); }
    let keys = set.validators.iter().enumerate()
        .filter(|(i, _)| *i < 64 && att.vote_set >> i & 1 == 1)
        .map(|(_, v)| PublicKey::from_bytes(&v.vote_key))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::BadVoteKey)?;
    if keys.len() < set.quorum() { return Err(Error::NotEnoughVotes); }
    let sig = Signature::sig_validate(&att.agg_sig, true).map_err(|_| Error::BadSignature)?;
    match sig.fast_aggregate_verify(true, &att.data.hash(), BLS_DST, &keys.iter().collect::<Vec<_>>()) {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(Error::BadSignature),
    }
}

/// signers of `att` (bits over `signing`) whose vote key is in `trusted`: skipping epochs is
/// sound when >= 2/3 of a trusted set signed, whatever keys the rest of `signing` holds
pub fn trusted_signers(att: &Attestation, signing: &ValidatorSet, trusted: &ValidatorSet) -> usize {
    signing.validators.iter().enumerate()
        .filter(|(i, v)| *i < 64 && att.vote_set >> i & 1 == 1 && trusted.validators.iter().any(|t| t.vote_key == v.vote_key))
        .count()
}

/// (number, hash) an attestation finalizes: its source when the target is the direct child
pub fn finalized(att: &Attestation) -> Option<(u64, [u8; 32])> {
    (att.data.target_number == att.data.source_number + 1).then_some((att.data.source_number, att.data.source_hash))
}

/// headers ascending and parent-linked, ending at a block known final: all of them are final
pub fn verify_ancestry(headers: &[Header], final_hash: &[u8; 32]) -> Result<(), Error> {
    let last = headers.last().ok_or(Error::BrokenAncestry)?;
    let linked = headers.windows(2).all(|w| w[1].parent_hash == w[0].hash && w[1].number == w[0].number + 1);
    if !linked || &last.hash != final_hash { return Err(Error::BrokenAncestry); }
    Ok(())
}
