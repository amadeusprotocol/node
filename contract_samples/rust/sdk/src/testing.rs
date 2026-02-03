use std::collections::BTreeMap;
use std::vec::Vec;
use std::string::String;
use std::cell::RefCell;

thread_local! {
    static MOCK_STORAGE: RefCell<BTreeMap<Vec<u8>, Vec<u8>>> = RefCell::new(BTreeMap::new());
    static MOCK_CONTEXT: RefCell<MockContext> = RefCell::new(MockContext::default());
}

#[derive(Clone, Debug)]
pub struct MockContext {
    pub entry_slot: u64,
    pub entry_height: u64,
    pub entry_epoch: u64,
    pub entry_signer: Vec<u8>,
    pub tx_nonce: u64,
    pub tx_signer: Vec<u8>,
    pub account_current: Vec<u8>,
    pub account_caller: Vec<u8>,
    pub account_origin: Vec<u8>,
    pub attachment: Option<(Vec<u8>, Vec<u8>)>, // (symbol, amount)
    pub seed: Vec<u8>,
}

impl Default for MockContext {
    fn default() -> Self {
        Self {
            entry_slot: 0,
            entry_height: 0,
            entry_epoch: 0,
            entry_signer: Vec::new(),
            tx_nonce: 0,
            tx_signer: Vec::new(),
            account_current: Vec::new(),
            account_caller: Vec::new(),
            account_origin: Vec::new(),
            attachment: None,
            seed: vec![0u8; 32],
        }
    }
}

pub fn reset() {
    MOCK_STORAGE.with(|s| s.borrow_mut().clear());
    MOCK_CONTEXT.with(|c| *c.borrow_mut() = MockContext::default());
}

pub fn set_context(ctx: MockContext) {
    MOCK_CONTEXT.with(|c| *c.borrow_mut() = ctx);
}

pub fn get_storage() -> BTreeMap<Vec<u8>, Vec<u8>> {
    MOCK_STORAGE.with(|s| s.borrow().clone())
}

pub fn dump() -> String {
    MOCK_STORAGE.with(|s| {
        s.borrow()
            .iter()
            .map(|(k, v)| format!("{}={}", String::from_utf8_lossy(k), String::from_utf8_lossy(v)))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

#[allow(dead_code)]
pub(crate) mod mock_imports {
    use super::*;
    use crate::encoding::*;

    pub fn import_kv_get(key: &[u8]) -> Option<Vec<u8>> {
        MOCK_STORAGE.with(|s| s.borrow().get(key).cloned())
    }

    pub fn import_kv_exists(key: &[u8]) -> bool {
        MOCK_STORAGE.with(|s| s.borrow().contains_key(key))
    }

    pub fn import_kv_put(key: &[u8], value: &[u8]) {
        MOCK_STORAGE.with(|s| {
            s.borrow_mut().insert(key.to_vec(), value.to_vec());
        });
    }

    pub fn import_kv_increment(key: &[u8], amount: &[u8]) -> String {
        let amt = bytes_to_i128(amount);
        MOCK_STORAGE.with(|s| {
            let mut storage = s.borrow_mut();
            let current = storage.get(key)
                .map(|v| bytes_to_i128(v))
                .unwrap_or(0);
            let new_val = current + amt;
            storage.insert(key.to_vec(), i128_to_bytes(new_val));
            new_val.to_string()
        })
    }

    pub fn import_kv_delete(key: &[u8]) {
        MOCK_STORAGE.with(|s| {
            s.borrow_mut().remove(key);
        });
    }

    pub fn import_kv_get_prev(prefix: &[u8], key: &[u8]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        MOCK_STORAGE.with(|s| {
            let storage = s.borrow();
            let full_key = if key.is_empty() {
                prefix.to_vec()
            } else {
                [prefix, key].concat()
            };

            let mut found = None;
            for (k, v) in storage.iter().rev() {
                if k.starts_with(prefix) && k < &full_key {
                    found = Some((k.clone(), v.clone()));
                    break;
                }
            }

            match found {
                Some((k, v)) => (Some(k), Some(v)),
                None => (None, None),
            }
        })
    }

    pub fn import_kv_get_next(prefix: &[u8], key: &[u8]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        MOCK_STORAGE.with(|s| {
            let storage = s.borrow();
            let full_key = if key.is_empty() {
                prefix.to_vec()
            } else {
                [prefix, key].concat()
            };

            let mut found = None;
            for (k, v) in storage.iter() {
                if k.starts_with(prefix) && k > &full_key {
                    found = Some((k.clone(), v.clone()));
                    break;
                }
            }

            match found {
                Some((k, v)) => (Some(k), Some(v)),
                None => (None, None),
            }
        })
    }

    pub fn import_entry_slot() -> u64 {
        MOCK_CONTEXT.with(|c| c.borrow().entry_slot)
    }

    pub fn import_entry_height() -> u64 {
        MOCK_CONTEXT.with(|c| c.borrow().entry_height)
    }

    pub fn import_entry_epoch() -> u64 {
        MOCK_CONTEXT.with(|c| c.borrow().entry_epoch)
    }

    pub fn import_entry_signer() -> Vec<u8> {
        MOCK_CONTEXT.with(|c| c.borrow().entry_signer.clone())
    }

    pub fn import_tx_nonce() -> u64 {
        MOCK_CONTEXT.with(|c| c.borrow().tx_nonce)
    }

    pub fn import_tx_signer() -> Vec<u8> {
        MOCK_CONTEXT.with(|c| c.borrow().tx_signer.clone())
    }

    pub fn import_account_current() -> Vec<u8> {
        MOCK_CONTEXT.with(|c| c.borrow().account_current.clone())
    }

    pub fn import_account_caller() -> Vec<u8> {
        MOCK_CONTEXT.with(|c| c.borrow().account_caller.clone())
    }

    pub fn import_account_origin() -> Vec<u8> {
        MOCK_CONTEXT.with(|c| c.borrow().account_origin.clone())
    }

    pub fn import_get_attachment() -> (bool, (Vec<u8>, Vec<u8>)) {
        MOCK_CONTEXT.with(|c| {
            match &c.borrow().attachment {
                Some((symbol, amount)) => (true, (symbol.clone(), amount.clone())),
                None => (false, (Vec::new(), Vec::new())),
            }
        })
    }

    pub fn import_seed() -> Vec<u8> {
        MOCK_CONTEXT.with(|c| c.borrow().seed.clone())
    }

    pub fn import_log(msg: &str) {
        #[cfg(test)]
        println!("{}", msg);
    }
}

#[macro_export]
macro_rules! testing_env {
    ($ctx:expr) => {
        $crate::testing::set_context($ctx);
    };
}
