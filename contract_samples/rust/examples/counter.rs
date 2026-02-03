#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use amadeus_sdk::*;

#[no_mangle]
pub extern "C" fn init() {
    kv_put("inited", "true");
}

#[contract]
fn get() -> i128 {
    kv_get("the_counter").unwrap_or(0)
}

#[contract]
fn increment(amount: Vec<u8>) -> String {
    kv_increment("the_counter", amount)
}

#[contract]
fn increment_another_counter(contract: Vec<u8>) -> Vec<u8> {
    let incr_by = 3i64;
    log("increment_another_counter");
    call!(contract.as_slice(), "increment", [incr_by])
}
