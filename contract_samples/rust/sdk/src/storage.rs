use crate::Payload;
use crate::encoding::*;
use alloc::{vec::Vec, string::String};

pub trait FromKvBytes {
    fn from_bytes(data: Vec<u8>) -> Self;
}

impl FromKvBytes for Vec<u8> {
    fn from_bytes(data: Vec<u8>) -> Self { data }
}

impl FromKvBytes for String {
    fn from_bytes(data: Vec<u8>) -> Self {
        String::from_utf8(data).unwrap_or_default()
    }
}

macro_rules! impl_from_kv_bytes_for_int {
    ($type:ty, $converter:path) => {
        impl FromKvBytes for $type {
            fn from_bytes(data: Vec<u8>) -> Self {
                $converter(&data)
            }
        }
    };
}

impl_from_kv_bytes_for_int!(i8,  crate::encoding::bytes_to_i8);
impl_from_kv_bytes_for_int!(i16,  crate::encoding::bytes_to_i16);
impl_from_kv_bytes_for_int!(i32,  crate::encoding::bytes_to_i32);
impl_from_kv_bytes_for_int!(i64,  crate::encoding::bytes_to_i64);
impl_from_kv_bytes_for_int!(i128, crate::encoding::bytes_to_i128);

impl_from_kv_bytes_for_int!(u8,  crate::encoding::bytes_to_u8);
impl_from_kv_bytes_for_int!(u16,  crate::encoding::bytes_to_u16);
impl_from_kv_bytes_for_int!(u32,  crate::encoding::bytes_to_u32);
impl_from_kv_bytes_for_int!(u64,  crate::encoding::bytes_to_u64);
impl_from_kv_bytes_for_int!(u128, crate::encoding::bytes_to_u128);

#[cfg(not(any(test, feature = "testing")))]
extern "C" {
    fn import_kv_get(p: *const u8, l: usize) -> i32;
    fn import_kv_exists(p: *const u8, l: usize) -> i32;
    fn import_kv_get_prev(pp: *const u8, pl: usize, kp: *const u8, kl: usize) -> i32;
    fn import_kv_get_next(pp: *const u8, pl: usize, kp: *const u8, kl: usize) -> i32;

    fn import_kv_put(kp: *const u8, kl: usize, vp: *const u8, vl: usize);
    fn import_kv_increment(kp: *const u8, kl: usize, vp: *const u8, vl: usize) -> i32;
    fn import_kv_delete(p: *const u8, l: usize);
}

pub fn kv_put(key: impl Payload, value: impl Payload) {
    let key_cow = key.to_payload();
    let key_bytes = key_cow.as_ref();
    let value_cow = value.to_payload();
    let value_bytes = value_cow.as_ref();
    #[cfg(any(test, feature = "testing"))]
    {
        crate::testing::mock_imports::import_kv_put(key_bytes, value_bytes);
    }
    #[cfg(not(any(test, feature = "testing")))]
    unsafe {
        import_kv_put(
            key_bytes.as_ptr(),
            key_bytes.len(),
            value_bytes.as_ptr(),
            value_bytes.len()
        )
    }
}

pub fn kv_get<T: FromKvBytes>(key: impl Payload) -> Option<T> {
    let key_cow = key.to_payload();
    let key_bytes = key_cow.as_ref();
    #[cfg(any(test, feature = "testing"))]
    {
        crate::testing::mock_imports::import_kv_get(key_bytes).map(|data| T::from_bytes(data))
    }
    #[cfg(not(any(test, feature = "testing")))]
    unsafe {
        let ptr = import_kv_get(key_bytes.as_ptr(), key_bytes.len());
        if *(ptr as *const i32) == -1 {
            None
        } else {
            let raw_data = read_bytes(ptr);
            Some(T::from_bytes(raw_data))
        }
    }
}

pub fn kv_increment(key: impl Payload, amount: impl Payload) -> String {
    let key_cow = key.to_payload();
    let key_bytes = key_cow.as_ref();
    let amount_cow = amount.to_payload();
    let amount_bytes = amount_cow.as_ref();
    #[cfg(any(test, feature = "testing"))]
    {
        crate::testing::mock_imports::import_kv_increment(key_bytes, amount_bytes)
    }
    #[cfg(not(any(test, feature = "testing")))]
    unsafe {
        read_string(import_kv_increment(
            key_bytes.as_ptr(),
            key_bytes.len(),
            amount_bytes.as_ptr(),
            amount_bytes.len()
        ))
    }
}

pub fn kv_delete(key: impl Payload) {
    let key_cow = key.to_payload();
    let key_bytes = key_cow.as_ref();
    #[cfg(any(test, feature = "testing"))]
    {
        crate::testing::mock_imports::import_kv_delete(key_bytes);
    }
    #[cfg(not(any(test, feature = "testing")))]
    unsafe {
        import_kv_delete(
            key_bytes.as_ptr(),
            key_bytes.len()
        )
    }
}

pub fn kv_exists(key: impl Payload) -> bool {
    let key_cow = key.to_payload();
    let key_bytes = key_cow.as_ref();
    #[cfg(any(test, feature = "testing"))]
    {
        crate::testing::mock_imports::import_kv_exists(key_bytes)
    }
    #[cfg(not(any(test, feature = "testing")))]
    unsafe {
        let result = import_kv_exists(key_bytes.as_ptr(), key_bytes.len());
        result == 1
    }
}

pub fn kv_get_prev(prefix: impl Payload, key: impl Payload) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let prefix_cow = prefix.to_payload();
    let prefix_bytes = prefix_cow.as_ref();
    let key_cow = key.to_payload();
    let key_bytes = key_cow.as_ref();
    #[cfg(any(test, feature = "testing"))]
    {
        crate::testing::mock_imports::import_kv_get_prev(prefix_bytes, key_bytes)
    }
    #[cfg(not(any(test, feature = "testing")))]
    unsafe {
        let ptr = import_kv_get_prev(prefix_bytes.as_ptr(), prefix_bytes.len(), key_bytes.as_ptr(), key_bytes.len());
        let len = *(ptr as *const i32);
        if len == -1 {
            return (None, None)
        } else {
            (Some(read_bytes(ptr)), Some(read_bytes(ptr + 4 + len)))
        }
    }
}

pub fn kv_get_next(prefix: impl Payload, key: impl Payload) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let prefix_cow = prefix.to_payload();
    let prefix_bytes = prefix_cow.as_ref();
    let key_cow = key.to_payload();
    let key_bytes = key_cow.as_ref();
    #[cfg(any(test, feature = "testing"))]
    {
        crate::testing::mock_imports::import_kv_get_next(prefix_bytes, key_bytes)
    }
    #[cfg(not(any(test, feature = "testing")))]
    unsafe {
        let ptr = import_kv_get_next(prefix_bytes.as_ptr(), prefix_bytes.len(), key_bytes.as_ptr(), key_bytes.len());
        let len = *(ptr as *const i32);
        if len == -1 {
            return (None, None)
        } else {
            (Some(read_bytes(ptr)), Some(read_bytes(ptr + 4 + len)))
        }
    }
}
