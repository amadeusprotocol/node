defmodule Entry do
    _ = """
    entry %{
        header %{
            slot: 9,
            height: 6,
            prev_slot: 5,
            prev_hash: <<>>,
            signer: <>,
            dr <hash(prev_dr)>
            vr <sign(prev_vr)>
            txs_hash: <32>
        }
        txs []
        hash <header>
        sig <hash>
        optional|mask <bits>
    }

    entry %{
        header %{
            height: 6,
            prev_hash: <<>>,
            proposer: <>,
            dr <hash(prev_dr)>
            vr <sign(prev_vr)>
            tx_root: <32>   0 1 2 3 4 txs_count txs_hash
            validator_root: 0 1 2 3 4 validators_count validators_hash last_validators_change
            chain_root:     0 1 2 3 4 chain_id chain_tip chain_tip_height (leave out for a future update)
        }
        hash <header>
        aggsig { (mask_size always 1 if proposer is not 0) (if proposer is 0, it means proposer is down and VDF executed + network arrived at empty block)
          signature
          mask
          mask_size
          mask_set_size
        }
        txs []
    }
    h (header)

    consensus %{
      receipts_logs_extra_root: <32>,
      state_root: <32>, all_contract_state
      entry_hash: <32>,
      aggsig: %{
        mask: <<0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0>>,
        aggsig: <96>,
        mask_size: 99,
        mask_set_size: 1
      }
    }
    h (entry_hash || state_root || receipts_logs_extra_root)
    """

    # :root_chain — PHASE 1 schema-only rollout.
    # The field is whitelisted in @fields_header on every node, but proposers
    # do NOT populate it yet (see build_next/3 below). Because Map.take only
    # picks keys that exist on the source, current blocks (which don't carry
    # the key) hash identically to pre-rollout. Once enough peers have shipped
    # Phase 1, the next release flips proposers on (Phase 2). Old nodes that
    # missed Phase 1 will reject Phase-2 blocks.
    @fields [:header, :hash, :signature, :txs, :mask, :mask_size, :mask_set_size]
    @fields_header [:height, :prev_hash, :slot, :prev_slot, :signer, :dr, :vr, :root_tx, :root_validator, :root_chain]

    def unpack_from_db(nil), do: nil
    def unpack_from_db(entry_packed) do
        entry = if is_binary(entry_packed) do RDB.vecpak_decode(entry_packed) else entry_packed end
        Map.take(entry, @fields)
    end

    def pack_for_db(entry_packed) when is_binary(entry_packed) do entry_packed end
    def pack_for_db(entry) do
        entry = Map.take(entry, @fields)
        entry_header = Map.take(entry.header, @fields_header)
        entry = Map.put(entry, :header, entry_header)
        RDB.vecpak_encode(entry)
    end

    def unpack_from_net(nil), do: nil
    def unpack_from_net(entry) do
        entry = Map.take(entry, @fields)
        entry_header = Map.take(entry.header, @fields_header)
        entry = Map.put(entry, :header, entry_header)
        if !entry[:mask] do entry else
          trainers = DB.Chain.validators_for_height(entry_header.height)
          true = is_integer(entry.mask_size)
          true = is_integer(entry.mask_set_size)
          true = is_bitstring(entry.mask)
          true = entry.mask_size == length(trainers)
          true = bit_size(entry.mask) >= entry.mask_size

          trainers_signed = BLS12AggSig.unmask_trainers(trainers, entry.mask, entry.mask_size)
          true = entry.mask_set_size == length(trainers_signed)
          entry
        end
    end

    def pack_for_net(entry) do
      entry = Map.take(entry, @fields)
      entry_header = Map.take(entry.header, @fields_header)
      Map.put(entry, :header, entry_header)
    end

    def unpack_and_validate_from_net(entry) do
        try do
        entry = unpack_from_net(entry)

        res_sig = validate_signature(entry, true)
        if res_sig.error != :ok, do: throw res_sig

        entry = Map.put(entry, :hash, res_sig.hash)
        res_entry = validate_entry(entry, res_sig.hash)
        if res_entry.error != :ok, do: throw res_entry

        %{error: :ok, entry: entry}
        catch
            :throw,r -> r
            e,r -> IO.inspect {Entry, :unpack_and_validate, e, r, __STACKTRACE__}; %{error: :unknown}
        end
    end

    def validate_entry(e, hash \\ nil) do
        try do
        eh = e.header
        hash = hash || header_hash(eh)
        validate_hash(e, hash)

        if !is_integer(eh.slot), do: throw(%{error: :slot_not_integer})
        if !is_integer(eh.prev_slot), do: throw(%{error: :prev_slot_not_integer})
        if !is_integer(eh.height), do: throw(%{error: :height_not_integer})
        if !is_binary(eh.prev_hash), do: throw(%{error: :prev_hash_not_binary})
        if byte_size(eh.prev_hash) != 32, do: throw(%{error: :prev_hash_not_256_bits})
        if !is_binary(eh.dr), do: throw(%{error: :dr_not_binary})
        if byte_size(eh.dr) != 32, do: throw(%{error: :dr_not_256_bits})
        if !is_binary(eh.vr), do: throw(%{error: :vr_not_binary})
        if byte_size(eh.vr) != 96, do: throw(%{error: :vr_not_96_bytes})
        if !is_binary(eh.signer), do: throw(%{error: :signer_not_binary})
        if byte_size(eh.signer) != 48, do: throw(%{error: :signer_not_48_bytes})

        if !!e[:mask] and !is_bitstring(e.mask), do: throw(%{error: :mask_not_bitstring})

        if !is_list(e.txs), do: throw(%{error: :txs_not_list})
        if length(e.txs) > 100, do: throw(%{error: :TEMPORARY_txs_only_100_per_entry})

        if !is_binary(eh.root_tx), do: throw(%{error: :root_tx_not_binary})
        if byte_size(eh.root_tx) != 32, do: throw(%{error: :root_tx_not_256_bits})
        if eh.root_tx != root_tx(Enum.map(e.txs, & &1.hash)), do: throw(%{error: :root_tx_invalid})

        if !is_binary(eh.root_validator), do: throw(%{error: :root_validator_not_binary})
        if byte_size(eh.root_validator) != 32, do: throw(%{error: :root_validator_not_256_bits})
        validators = DB.Chain.validators_for_height(eh.height)
        validators_last_change_height = DB.Chain.validators_last_change_height(eh.height)
        if eh.root_validator != root_validator(validators, validators_last_change_height), do: throw(%{error: :root_validator_invalid})

        is_special_meeting_block = !!e[:mask]
        steam = Task.async_stream(e.txs, fn txu ->
          %{error: err} = TX.validate(txu, is_special_meeting_block)
          err
        end)
        err = Enum.find_value(steam, fn {:ok, result} -> result != :ok && result end)
        if err, do: throw(err)

        throw(%{error: :ok})
        catch
            :throw,r -> r
            e,r -> IO.inspect {Entry, :validate_entry, e, r}; %{error: :unknown}
        end
    end

    def validate_signature(e, require_hash \\ false) do
        header = e.header
        hash = header_hash(header)
        mask = e[:mask]
        try do
          if require_hash, do: validate_hash(e, hash)

          if mask do
              trainers = DB.Chain.validators_for_height(header.height)
              if !is_integer(e.mask_size), do: throw(%{error: :mask_size_not_integer})
              if !is_bitstring(e.mask), do: throw(%{error: :mask_not_bitstring})
              if e.mask_size != length(trainers), do: throw(%{error: :mask_size_mismatch})
              if bit_size(e.mask) < e.mask_size, do: throw(%{error: :mask_too_short})

              trainers_signed = BLS12AggSig.unmask_trainers(trainers, e.mask, e.mask_size)
              if nil in trainers_signed, do: throw(%{error: :wrong_epoch})

              aggpk = BlsEx.aggregate_public_keys!(trainers_signed)
              if !BlsEx.verify?(aggpk, e.signature, hash, BLS12AggSig.dst_entry()), do: throw(%{error: :invalid_mask_signature})
          else
              if !BlsEx.verify?(header.signer, e.signature, hash, BLS12AggSig.dst_entry()), do: throw(%{error: :invalid_signature})
          end
          %{error: :ok, hash: hash}
        catch
            :throw,r -> Map.put(r, :hash, hash)
            e,r -> IO.inspect({Entry, :validate_signature, e, r, __STACKTRACE__}, limit: 1111111); %{error: :unknown, hash: hash}
        end
    end

    defp header_hash(header) do
        :crypto.hash(:sha256, RDB.vecpak_encode(header))
    end

    defp validate_hash(entry, hash) do
        cond do
            !is_binary(entry[:hash]) -> throw(%{error: :hash_not_binary})
            byte_size(entry.hash) != 32 -> throw(%{error: :hash_not_256_bits})
            entry.hash != hash -> throw(%{error: :invalid_hash})
            true -> true
        end
    end

    def validate_next(cur_entry, next_entry) do
        try do
        ceh = cur_entry.header
        neh = next_entry.header
        if ceh.slot != neh.prev_slot, do: throw(%{error: :invalid_slot})
        if ceh.height != (neh.height - 1), do: throw(%{error: :invalid_height})
        if cur_entry.hash != neh.prev_hash, do: throw(%{error: :invalid_hash})

        if :crypto.hash(:sha256, ceh.dr) != neh.dr, do: throw(%{error: :invalid_dr})
        if !BlsEx.verify?(neh.signer, neh.vr, ceh.vr, BLS12AggSig.dst_vrf()), do: throw(%{error: :invalid_vr})

        # root_chain soft validation (log-only for now). Only runs when the
        # proposer set the field AND our local MMR is in sync at this height.
        # Filters bad blocks out of the candidate pool BEFORE expensive
        # contract exec in apply_entry — so a persistently bad block doesn't
        # DoS our apply path. Flip the IO.inspect to a `throw` to enforce.
        case neh[:root_chain] do
          nil -> :ok
          theirs ->
            mmr = DB.MMR.load_or_empty()
            if mmr.size == neh.height do
              ours = MMR.root_chain(DB.MMR.chain_id(), mmr)
              if theirs != ours do
                IO.inspect(
                  {:root_chain_mismatch, neh.height,
                    ours: Base.encode16(ours, case: :lower),
                    theirs: Base.encode16(theirs, case: :lower)}
                )
                # throw(%{error: :root_chain_mismatch})
              end
            end
        end

        chain_epoch = div(neh.height, 100_000)
        chain_height = neh.height
        segment_vr_hash = DB.Chain.segment_vr_hash()
        diff_bits = DB.Chain.diff_bits()

        Enum.reduce(next_entry.txs, %{}, fn(txu, batch_state)->
            case TXPool.validate_tx(txu, %{epoch: chain_epoch, height: chain_height, segment_vr_hash: segment_vr_hash, diff_bits: diff_bits, batch_state: batch_state}) do
              %{error: :ok, batch_state: batch_state} -> batch_state
              %{error: error} when error in [:invalid_tx_nonce, :not_enough_tx_exec_balance] -> throw %{error: error}
              _ -> batch_state
            end
        end)

        %{error: :ok}
        catch
            :throw,r -> r
            e,r ->
                IO.inspect {Entry, :validate_next, e, r}
                %{error: :unknown}
        end
    end

    def build_next(seed, cur_entry, txus) do
        next_height = cur_entry.header.height + 1
        pk = BlsEx.get_public_key!(seed)

        dr = :crypto.hash(:sha256, cur_entry.header.dr)
        vr = BlsEx.sign!(seed, cur_entry.header.vr, BLS12AggSig.dst_vrf())

        validators = DB.Chain.validators_for_height(next_height)
        validators_last_change_height = DB.Chain.validators_last_change_height(next_height)

        %{
            header: %{
                slot: cur_entry.header.slot + 1,
                height: next_height,
                prev_slot: cur_entry.header.slot,
                prev_hash: cur_entry.hash,
                dr: dr,
                vr: vr,
                signer: pk,
                root_tx: root_tx(Enum.map(txus, & &1.hash)),
                root_validator: root_validator(validators, validators_last_change_height)
            },
            txs: txus
        }
    end

    def sign(seed, entry) do
        hash = :crypto.hash(:sha256, RDB.vecpak_encode(entry.header))
        signature = BlsEx.sign!(seed, hash, BLS12AggSig.dst_entry())
        %{
            header: entry.header,
            hash: hash,
            signature: signature,
            txs: entry.txs,
        }
    end

    def epoch(entry) do
        div(entry.header.height, 100_000)
    end

    def height(entry) do
        entry.header.height
    end

    def root_tx(hashes) do
      RDB.bintree_root(root_tx_build(hashes))
    end
    def root_tx_build(hashes) do
      by_index_hash = Enum.flat_map(Enum.with_index(hashes), fn{hash, index}->
        [{nil, hash, "#{index}"}]
      end)
      by_index_hash ++ [{nil, "count", "#{length(hashes)}"}]
    end

    def root_validator(validator_pks, last_change_height) do
      RDB.bintree_root(root_validator_build(validator_pks, last_change_height))
    end
    def root_validator_build(validator_pks, last_change_height) do
      by_index_hash = Enum.flat_map(Enum.with_index(validator_pks), fn{hash, index}->
        [{nil, hash, "#{index}"}]
      end)
      kvs = by_index_hash ++ [{nil, "count", "#{length(validator_pks)}"}]
      kvs ++ [{nil, "hash", :crypto.hash(:sha256, Enum.join(validator_pks))}, {nil, "last_change_height", "#{last_change_height}"}]
    end

    def root_block() do
      #TODO for future
      #proof of inclusion for previous blocks
    end

    def proof_tx_included(entry_hash, tx_hash) do
      entry = DB.Entry.by_hash(entry_hash)
      tx_hashes = Enum.map(entry.txs, & &1.hash)
      kvs = root_tx_build(tx_hashes)
      RDB.bintree_root_prove(kvs, nil, tx_hash)

      #p = Entry.proof_tx_included Base58.decode("BzF3P2a5gMpQ2FwAuiftHC85BnDfxcmYXPfW95BmNnXU"), Base58.decode("3ySbVoruCQsGb9K1XkRbQdm5WSuxnEoVCugAUj6qouS6")
      #RDB.bintree_root_verify2(p, nil, Base58.decode("3ySbVoruCQsGb9K1XkRbQdm5WSuxnEoVCugAUj6qouS6"), "0")
    end

    def proof_validators(entry_hash) do
      entry = DB.Entry.by_hash(entry_hash)

      validators = DB.Chain.validators_for_height(entry.header.height)
      validators_last_change_height = DB.Chain.validators_last_change_height(entry.header.height)

      hash = :crypto.hash(:sha256, Enum.join(validators))

      kvs = root_validator_build(validators, validators_last_change_height)
      proof = RDB.bintree_root_prove(kvs, "hash")
      %{proof: proof, key: "hash", value: hash, validators: validators}
    end
end
