rustler::atoms! {
    ok,
    error,
    nil,
    mutex_closed,

    invalid_iterator,
    // Iterator control atoms
    iterator_mode,
    start,
    end,
    from,
    forward,
    reverse,
    next,


    //ama stuff because cant compile as rlib :()
    hash,
    header,
    signature,
    mask,
    txs,

    entry_signer,
    entry_prev_hash,
    entry_vr,
    entry_vr_b3,
    entry_dr,

    entry_slot,
    entry_prev_slot,
    entry_height,
    entry_epoch,
    entry_full,

    tx,
    tx_encoded,
    signer,
    nonce,
    action,
    op,
    contract,
    function,
    args,
    attached_symbol,
    attached_amount,

    member,
    nonmember,
    missing_subindex,
    missing_stem_empty_subtree,
    missing_stem_other_stem,

    tx_cost,
    tx_historical_cost,

    direction,
    len,
    root,
    path,
    nodes,

    siblings,
    terminus,
    empty,
    identity_hash,
    value_hash,

    invalid,
    included,
    mismatch,
    nonexistance,

    forkheight,

    ama_1_dollar,
    ama_10_cent,
    ama_1_cent,

    reserve_ama_per_tx_exec,
    reserve_ama_per_tx_storage,

    cost_per_byte_historical,
    cost_per_byte_state,
    cost_per_op_wasm,

    cost_per_db_read_base,
    cost_per_db_read_byte,
    cost_per_db_write_base,
    cost_per_db_write_byte,

    cost_per_sol,
    cost_per_new_leaf_merkle,

    txid,
    success,
    exec_used,
    result,
    logs,
}
