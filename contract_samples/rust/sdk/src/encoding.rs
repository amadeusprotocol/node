use alloc::{vec::Vec, string::{String, ToString}};

pub fn read_bytes(ptr: i32) -> Vec<u8> {
    unsafe {
        let len = *(ptr as *const i32);
        let data = (ptr + 4) as *const u8;
        core::slice::from_raw_parts(data, len as usize).to_vec()
    }
}

pub fn read_string(ptr: i32) -> String {
    String::from_utf8(read_bytes(ptr)).unwrap_or_default()
}

pub fn read_u64(ptr: i32) -> u64 {
    unsafe { *(ptr as *const u64) }
}

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn b58_encode(input: &[u8]) -> String {
    let mut d = Vec::new();
    let mut r = String::new();
    for &byte in input {
        let mut carry = byte as u32;
        let mut j = 0;
        if carry == 0 && r.is_empty() && byte != input[0] { r.push('1'); }
        while j < d.len() || carry != 0 {
            let n = if j < d.len() { d[j] as u32 * 256 + carry } else { carry };
            carry = n / 58;
            if j < d.len() { d[j] = (n % 58) as u8; } else { d.push((n % 58) as u8); }
            j += 1;
        }
    }
    for i in (0..d.len()).rev() { r.push(B58[d[i] as usize] as char); }
    r
}

pub fn b58_decode(input: &str) -> Option<Vec<u8>> {
    let mut d = Vec::new();
    let mut b = Vec::new();
    for c in input.chars() {
        let pos = B58.iter().position(|&x| x == c as u8)?;
        let mut carry = pos;
        let mut j = 0;
        if carry == 0 && b.is_empty() && c != input.chars().next()? { b.push(0); }
        while j < d.len() || carry != 0 {
            let n = if j < d.len() { d[j] * 58 + carry } else { carry };
            carry = n >> 8;
            if j < d.len() { d[j] = n & 0xff; } else { d.push(n & 0xff); }
            j += 1;
        }
    }
    for i in (0..d.len()).rev() { b.push(d[i] as u8); }
    Some(b)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut r = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        r.push(HEX[(b >> 4) as usize] as char);
        r.push(HEX[(b & 0xF) as usize] as char);
    }
    r
}

pub fn coin_raw(amount: u64, decimals: u32) -> Vec<u8> {
    let mut m = 1u64;
    for _ in 0..decimals { m *= 10; }
    (amount * m).to_string().as_bytes().to_vec()
}

macro_rules! impl_bytes_to_int {
    ($fn_name:ident, $type:ty) => {
        pub fn $fn_name(data: &[u8]) -> $type {
            let s = match core::str::from_utf8(data) {
                Ok(s) => s.trim(),
                Err(_) => $crate::abort!("invalid_utf8_string_as_integer"),
            };

            match s.parse::<$type>() {
                Ok(n) => n,
                Err(_) => $crate::abort!("invalid_integer_format"),
            }
        }
    };
}

impl_bytes_to_int!(bytes_to_i8, i8);
impl_bytes_to_int!(bytes_to_i16, i16);
impl_bytes_to_int!(bytes_to_i32, i32);
impl_bytes_to_int!(bytes_to_i64, i64);
impl_bytes_to_int!(bytes_to_i128, i128);
impl_bytes_to_int!(bytes_to_u8, u8);
impl_bytes_to_int!(bytes_to_u16, u16);
impl_bytes_to_int!(bytes_to_u32, u32);
impl_bytes_to_int!(bytes_to_u64, u64);
impl_bytes_to_int!(bytes_to_u128, u128);

pub fn i128_to_bytes(val: i128) -> Vec<u8> {
    use alloc::string::ToString;
    val.to_string().into_bytes()
}
