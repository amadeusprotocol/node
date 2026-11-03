#![no_std]
#![no_main]

fn dispatch(_f: &[u8]) {
    let mut x: u64 = 1;
    loop {
        x = core::hint::black_box(x.wrapping_mul(6364136223846793005).wrapping_add(1));
    }
}

amadeus_contract::entry!(dispatch);
