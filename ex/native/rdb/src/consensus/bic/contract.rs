use crate::bcat;
use crate::consensus::bic::wasm::validate_contract;
use crate::consensus::consensus_kv::{kv_get, kv_put};
use std::panic::panic_any;

pub fn call_deploy(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() == 0 {
        panic_any("invalid_args")
    }
    let wasmbytes = args[0].as_slice();
    validate_contract(env, wasmbytes);
    kv_put(env, &bcat(&[b"account:", &env.caller_env.account_caller, b":attribute:bytecode"]), wasmbytes);
    if args.len() >= 2 {
        let og_account_current = env.caller_env.account_current.clone();
        let og_account_caller = env.caller_env.account_caller.clone();

        env.caller_env.account_current = og_account_caller.clone();
        env.caller_env.account_caller = og_account_current.clone();
        env.caller_env.call_counter = env.caller_env.call_counter.saturating_add(1);
        env.caller_env.call_return_value = Vec::new();

        let init_function = args[1].as_slice().to_vec();
        let init_args = args[2..].to_vec();
        crate::consensus::consensus_apply::call_wasmvm(env, og_account_caller.clone(), init_function, init_args, None, None);

        env.caller_env.account_current = og_account_current;
        env.caller_env.account_caller = og_account_caller;
    }
}

pub fn bytecode(env: &mut crate::consensus::consensus_apply::ApplyEnv, account: &[u8]) -> Option<Vec<u8>> {
    kv_get(env, &bcat(&[b"account:", &account, b":attribute:bytecode"]))
}
