use crate::Payload;
use crate::encoding::*;
use alloc::{vec, borrow::Cow, vec::Vec};

pub const BURN_ADDRESS: &[u8] = &[0u8; 48];

#[cfg(not(test))]
pub fn seed() -> Vec<u8> { read_bytes(1100) }
#[cfg(test)]
pub fn seed() -> Vec<u8> { crate::testing::mock_imports::import_seed() }

#[cfg(not(test))]
pub fn entry_slot() -> u64 { read_u64(2000) }
#[cfg(test)]
pub fn entry_slot() -> u64 { crate::testing::mock_imports::import_entry_slot() }

#[cfg(not(test))]
pub fn entry_height() -> u64 { read_u64(2010) }
#[cfg(test)]
pub fn entry_height() -> u64 { crate::testing::mock_imports::import_entry_height() }

#[cfg(not(test))]
pub fn entry_epoch() -> u64 { read_u64(2020) }
#[cfg(test)]
pub fn entry_epoch() -> u64 { crate::testing::mock_imports::import_entry_epoch() }

#[cfg(not(test))]
pub fn entry_signer() -> Vec<u8> { read_bytes(2100) }
#[cfg(test)]
pub fn entry_signer() -> Vec<u8> { crate::testing::mock_imports::import_entry_signer() }

#[cfg(not(test))]
pub fn entry_prev_hash() -> Vec<u8> { read_bytes(2200) }
#[cfg(test)]
pub fn entry_prev_hash() -> Vec<u8> { Vec::new() } // Not mocked yet

#[cfg(not(test))]
pub fn entry_vr() -> Vec<u8> { read_bytes(2300) }
#[cfg(test)]
pub fn entry_vr() -> Vec<u8> { Vec::new() } // Not mocked yet

#[cfg(not(test))]
pub fn entry_dr() -> Vec<u8> { read_bytes(2400) }
#[cfg(test)]
pub fn entry_dr() -> Vec<u8> { Vec::new() } // Not mocked yet

#[cfg(not(test))]
pub fn tx_nonce() -> u64 { read_u64(3000) }
#[cfg(test)]
pub fn tx_nonce() -> u64 { crate::testing::mock_imports::import_tx_nonce() }

#[cfg(not(test))]
pub fn tx_signer() -> Vec<u8> { read_bytes(3100) }
#[cfg(test)]
pub fn tx_signer() -> Vec<u8> { crate::testing::mock_imports::import_tx_signer() }

#[cfg(not(test))]
pub fn account_current() -> Vec<u8> { read_bytes(4000) }
#[cfg(test)]
pub fn account_current() -> Vec<u8> { crate::testing::mock_imports::import_account_current() }

#[cfg(not(test))]
pub fn account_caller() -> Vec<u8> { read_bytes(4100) }
#[cfg(test)]
pub fn account_caller() -> Vec<u8> { crate::testing::mock_imports::import_account_caller() }

#[cfg(not(test))]
pub fn account_origin() -> Vec<u8> { read_bytes(4200) }
#[cfg(test)]
pub fn account_origin() -> Vec<u8> { crate::testing::mock_imports::import_account_origin() }

#[cfg(not(test))]
pub fn attached_symbol() -> Vec<u8> { read_bytes(5000) }
#[cfg(test)]
pub fn attached_symbol() -> Vec<u8> {
    let (has, (symbol, _)) = crate::testing::mock_imports::import_get_attachment();
    if has { symbol } else { Vec::new() }
}

#[cfg(not(test))]
pub fn attached_amount() -> Vec<u8> { read_bytes(5100) }
#[cfg(test)]
pub fn attached_amount() -> Vec<u8> {
    let (has, (_, amount)) = crate::testing::mock_imports::import_get_attachment();
    if has { amount } else { Vec::new() }
}

#[cfg(not(test))]
pub fn get_attachment() -> (bool, (Vec<u8>, Vec<u8>)) {
    unsafe {
        let header = core::ptr::read_unaligned(5000 as *const u32);
        if header == 0 {
            return (false, (Vec::new(), Vec::new()));
        }
    }
    (true, (attached_symbol(), attached_amount()))
}

#[cfg(test)]
pub fn get_attachment() -> (bool, (Vec<u8>, Vec<u8>)) {
    crate::testing::mock_imports::import_get_attachment()
}

#[cfg(not(any(test, feature = "testing")))]
extern "C" {
    fn import_log(p: *const u8, l: usize);
    fn import_return(p: *const u8, l: usize);
    fn import_call(args_ptr: *const u8, extra_args_ptr: *const u8) -> i32;
}

#[allow(dead_code)]
fn build_table(items: &[alloc::borrow::Cow<[u8]>]) -> Vec<u8> {
    let count = items.len();
    let table_size = 4 + (count * 8);
    let mut table = vec![0u8; table_size];
    let count_bytes = (count as u32).to_le_bytes();
    table[0..4].copy_from_slice(&count_bytes);
    for (i, item) in items.iter().enumerate() {
        let bytes = item.as_ref();
        let ptr_val = bytes.as_ptr() as u32;
        let len_val = bytes.len() as u32;
        let offset = 4 + (i * 8);
        table[offset..offset+4].copy_from_slice(&ptr_val.to_le_bytes());
        table[offset+4..offset+8].copy_from_slice(&len_val.to_le_bytes());
    }
    table
}

pub fn log(line: impl Payload) {
    let line_cow = line.to_payload();
    let line_bytes = line_cow.as_ref();
    #[cfg(any(test, feature = "testing"))]
    {
        let s = alloc::string::String::from_utf8_lossy(line_bytes);
        crate::testing::mock_imports::import_log(&s);
    }
    #[cfg(not(any(test, feature = "testing")))]
    unsafe { import_log(line_bytes.as_ptr(), line_bytes.len()); }
}

#[allow(unused_variables)]
pub fn ret(val: impl Payload) {
    #[cfg(not(any(test, feature = "testing")))]
    {
        let val_cow = val.to_payload();
        let val_bytes = val_cow.as_ref();
        unsafe { import_return(val_bytes.as_ptr(), val_bytes.len()); }
    }
}

#[cfg(not(any(test, feature = "testing")))]
pub fn call(contract: impl Payload, func: impl Payload, args: &[&dyn Payload], extra_args: &[&dyn Payload]) -> Vec<u8> {
    let mut main_owners = Vec::with_capacity(2 + args.len());
    main_owners.push(contract.to_payload());
    main_owners.push(func.to_payload());
    for arg in args {
        main_owners.push(arg.to_payload());
    }
    let main_table = build_table(&main_owners);
    let (_extra_owners, extra_ptr) = if extra_args.is_empty() {
        (Vec::new(), core::ptr::null())
    } else {
        let mut owners = Vec::with_capacity(extra_args.len());
        for arg in extra_args {
            owners.push(arg.to_payload());
        }
        let t = build_table(&owners);
        (owners, t.as_ptr())
    };
    unsafe {
        read_bytes(import_call(main_table.as_ptr(), extra_ptr))
    }
}

#[cfg(any(test, feature = "testing"))]
pub fn call(_contract: impl Payload, _func: impl Payload, _args: &[&dyn Payload], _extra_args: &[&dyn Payload]) -> Vec<u8> {
    Vec::new()
}

#[macro_export]
macro_rules! call {
    ($contract:expr, $func:expr, [ $( $arg:expr ),* ], [ $( $earg:expr ),* ]) => {
        {
            let args_slice: &[&dyn $crate::Payload] = &[ $( &$arg ),* ];
            let extra_slice: &[&dyn $crate::Payload] = &[ $( &$earg ),* ];
            $crate::call($contract, $func, args_slice, extra_slice)
        }
    };

    ($contract:expr, $func:expr, [ $( $arg:expr ),* ]) => {
        {
            let args_slice: &[&dyn $crate::Payload] = &[ $( &$arg ),* ];
            let empty_extra: &[&dyn $crate::Payload] = &[];
            $crate::call($contract, $func, args_slice, empty_extra)
        }
    };
}
