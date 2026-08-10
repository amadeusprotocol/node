#![cfg(test)]

use crate::bcat;
use crate::consensus::bic::protocol;
use crate::consensus::consensus_apply::call_wasmvm;
use crate::consensus::tests::chain_harness::{panic_message, Chain};
use std::panic::{catch_unwind, AssertUnwindSafe};

const MINIMAL_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // module header
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // () -> () type
    0x03, 0x02, 0x01, 0x00, // one function using type 0
    0x07, 0x07, 0x01, 0x03, b'r', b'u', b'n', 0x00, 0x00, // export run
    0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // empty function body
];

fn call_with_attachment(chain: &Chain, caller: &[u8], contract: &[u8], symbol: &[u8]) -> Result<Vec<u8>, String> {
    catch_unwind(AssertUnwindSafe(|| {
        chain.with_env(caller, |env| {
            env.exec_left = protocol::AMA_10_CENT;
            env.exec_max = protocol::AMA_10_CENT;
            call_wasmvm(env, contract.to_vec(), b"run".to_vec(), Vec::new(), Some(symbol.to_vec()), Some(b"1".to_vec()))
        })
    }))
    .map_err(panic_message)
}

fn put_coin(chain: &Chain, caller: &[u8], symbol: &[u8]) {
    chain.put(&bcat(&[b"coin:", symbol, b":totalSupply"]), b"10");
    chain.put(&bcat(&[b"account:", caller, b":balance:", symbol]), b"10");
}

#[test]
fn wasm_attachments_enforce_coin_transfer_policies() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let contract = chain.wallet(0);
    chain.put(&bcat(&[b"account:", &contract.pk, b":attribute:bytecode"]), MINIMAL_WASM);

    chain.put(&bcat(&[b"account:", &caller.pk, b":balance:AMA"]), b"10");
    assert_eq!(call_with_attachment(&chain, &caller.pk, &contract.pk, b"AMA"), Ok(Vec::new()));
    assert_eq!(chain.get(&bcat(&[b"account:", &caller.pk, b":balance:AMA"])), Some(b"9".to_vec()));
    assert_eq!(chain.get(&bcat(&[b"account:", &contract.pk, b":balance:AMA"])), Some(b"1".to_vec()));

    put_coin(&chain, &caller.pk, b"PAUSED");
    chain.put(b"coin:PAUSED:pausable", b"true");
    chain.put(b"coin:PAUSED:paused", b"true");
    assert_eq!(call_with_attachment(&chain, &caller.pk, &contract.pk, b"PAUSED"), Err("paused".to_string()));

    put_coin(&chain, &caller.pk, b"SOULBOUND");
    chain.put(b"coin:SOULBOUND:soulbound", b"true");
    assert_eq!(call_with_attachment(&chain, &caller.pk, &contract.pk, b"SOULBOUND"), Err("soulbound".to_string()));

    for symbol in [b"PAUSED".as_slice(), b"SOULBOUND".as_slice()] {
        assert_eq!(chain.get(&bcat(&[b"account:", &contract.pk, b":balance:", symbol])), None);
        assert_eq!(chain.get(&bcat(&[b"account:", &caller.pk, b":balance:", symbol])).as_deref(), Some(b"10".as_slice()));
    }
}
