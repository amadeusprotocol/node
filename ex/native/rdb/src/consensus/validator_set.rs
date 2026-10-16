use crate::consensus::aggsig::{get_bit_be, unmask_trainers};
use crate::model::_codec;
use vecpak::Term;

/// Ordered epoch roster. Removing a validator only clears its MSB-first bit.
/// Both masks are byte vectors (Vecpak Binary), with no fixed validator limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    pub validators: Vec<Vec<u8>>,
    pub mask_active: Vec<u8>,
}

pub fn valid_mask(mask: &[u8], size: usize) -> bool {
    mask.len() == size.div_ceil(8)
        && (size % 8 == 0 || mask.last().is_some_and(|b| b & ((1 << (8 - size % 8)) - 1) == 0))
}

impl ValidatorSet {
    pub fn new(validators: Vec<Vec<u8>>) -> Self {
        let size = validators.len();
        let mut mask_active = vec![255; size.div_ceil(8)];
        if size % 8 != 0 {
            *mask_active.last_mut().unwrap() = 255 << (8 - size % 8);
        }
        Self { validators, mask_active }
    }

    pub fn decode(bytes: &[u8]) -> Self {
        let term = vecpak::decode(bytes).expect("invalid_validator_set");
        let (list, mask) = match &term {
            Term::List(list) => (list.as_slice(), None),
            Term::PropList(pairs) => (
                _codec::pl_get_list(pairs, b"validators"),
                Some(_codec::pl_get_bytes(pairs, b"mask_active").to_vec()),
            ),
            _ => panic!("invalid_validator_set"),
        };
        let validators = list.iter().map(|term| match term {
            Term::Binary(pk) => pk.clone(),
            _ => panic!("invalid_trainer_list_element"),
        }).collect();
        let mut set = Self::new(validators);
        if let Some(mask) = mask {
            assert!(valid_mask(&mask, set.validators.len()), "invalid_mask_active");
            set.mask_active = mask;
        }
        set
    }

    pub fn encode(&self) -> Vec<u8> {
        vecpak::encode(Term::PropList(vec![
            (Term::Binary(b"validators".to_vec()), Term::List(self.validators.iter().cloned().map(Term::Binary).collect())),
            (Term::Binary(b"mask_active".to_vec()), Term::Binary(self.mask_active.clone())),
        ])).unwrap()
    }

    pub fn active(&self) -> Vec<Vec<u8>> {
        unmask_trainers(&self.validators, &self.mask_active, self.validators.len()).into_iter().map(<[u8]>::to_vec).collect()
    }

    pub fn signers(&self, mask: &[u8], size: u64) -> Result<Vec<&[u8]>, &'static str> {
        if size != self.validators.len() as u64 || !valid_mask(mask, self.validators.len()) {
            return Err("invalid_mask_size");
        }
        if mask.iter().zip(&self.mask_active).any(|(signed, active)| signed & !active != 0) {
            return Err("inactive_signer");
        }
        Ok(unmask_trainers(&self.validators, mask, self.validators.len()))
    }

    pub fn remove(&mut self, pk: &[u8]) -> Result<(), &'static str> {
        let i = self.validators.iter().position(|v| v == pk).ok_or("invalid_trainer_pk")?;
        if !get_bit_be(&self.mask_active, i) {
            return Err("invalid_trainer_pk");
        }
        self.mask_active[i / 8] &= !(1 << (7 - i % 8));
        Ok(())
    }
}
