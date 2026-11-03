#![no_std]
#![no_main]

use amadeus_contract as c;

fn dispatch(f: &[u8]) {
    match f {
        b"inc" => {
            let by = c::arg(0).map(|a| c::atoi(&a)).unwrap_or(1);
            let v = c::kv_increment(b"count", by);
            let mut buf = [0u8; 48];
            c::ret(c::itoa(v, &mut buf));
        }
        b"get" => c::ret(&c::kv_get(b"count").unwrap_or_else(|| b"0".into())),
        _ => c::abort(b"unknown function"),
    }
}

c::entry!(dispatch);
