#![no_std]
#![no_main]

fn dispatch(_f: &[u8]) {}

amadeus_contract::entry!(dispatch);
