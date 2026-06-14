defmodule DB.Chain do
  import DB.API

  def tip(db_opts \\ %{}) do RocksDB.get("temporal_tip", db_handle(db_opts, :sysconf, %{})) end

  def tip_entry(db_opts \\ %{}) do
    DB.Entry.by_hash(tip(db_opts), db_opts)
  end

  def height(db_opts \\ %{}) do tip_entry(db_opts).header.height end
  def epoch(db_opts \\ %{}) do div(height(db_opts), 100_000) end

  def rooted_tip(db_opts \\ %{}) do RocksDB.get("rooted_tip", db_handle(db_opts, :sysconf, %{})) end

  def rooted_tip_entry(db_opts \\ %{}) do
    DB.Entry.by_hash(rooted_tip(db_opts), db_opts)
  end

  def rooted_height(db_opts \\ %{}) do
      entry = rooted_tip_entry(db_opts)
      if entry do
          entry.header.height
      end
  end

  def segment_vr_hash(db_opts \\ %{}) do
    RocksDB.get("bic:epoch:segment_vr_hash", db_handle(db_opts, :contractstate, %{}))
  end

  def diff_bits(db_opts \\ %{}) do
    RocksDB.get("bic:epoch:diff_bits", db_handle(db_opts, :contractstate, %{to_integer: true})) || 24
  end

  def total_sols(db_opts \\ %{}) do
    RocksDB.get("bic:epoch:total_sols", db_handle(db_opts, :contractstate, %{to_integer: true})) || 0
  end

  def pop(pk, db_opts \\ %{}) do
    RocksDB.get("account:#{pk}:attribute:pop", db_handle(db_opts, :contractstate, %{}))
  end

  def nonce(pk, db_opts \\ %{}) do
    RocksDB.get("account:#{pk}:attribute:nonce", db_handle(db_opts, :contractstate, %{to_integer: true}))
  end

  def tx_count(db_opts \\ %{}) do
    RocksDB.get("tx_count", db_handle(db_opts, :sysconf, %{to_integer: true})) || 0
  end

  def balance(pk, symbol \\ "AMA", db_opts \\ %{}) do
    RocksDB.get("account:#{pk}:balance:#{symbol}", db_handle(db_opts, :contractstate, %{to_integer: true})) || 0
  end

  def balance_nft(pk, collection, token, db_opts \\ %{}) do
    RocksDB.get("account:#{pk}:nft:#{collection}:#{token}", db_handle(db_opts, :contractstate, %{to_integer: true})) || 0
  end

  def tx(tx_hash, db_opts \\ %{}) do
      map = RocksDB.get(tx_hash, db_handle(db_opts, :tx, %{}))
      map && tx_from_map(map, db_opts)
  end

  def pruned_below_height(db_opts \\ %{}) do
    RocksDB.get("pruned_below_height", db_handle(db_opts, :sysconf, %{to_integer: true})) || 0
  end

  def set_pruned_below_height(height, db_opts \\ %{}) do
    RocksDB.put("pruned_below_height", :erlang.integer_to_binary(height), db_handle(db_opts, :sysconf, %{}))
  end

  def tx_from_map(map, db_opts \\ %{}) do
    map = map |> RDB.vecpak_decode()
    entry_bytes = RocksDB.get(map.entry_hash, db_handle(db_opts, :entry, %{}))
    if !entry_bytes, do: throw(%{error: :tx_entry_missing, entry_hash: map.entry_hash})
    entry = Entry.unpack_from_db(entry_bytes)
    tx_bytes = binary_part(entry_bytes, map.index_start, map.index_size)

    receipt = if map[:result] do map.result else map.receipt end

    status = cond do
      rooted_height() >= entry.header.height -> :finalized
      true -> :committed
    end
    TX.unpack(tx_bytes)
    |> Map.put(:receipt, receipt)
    |> Map.put(:metadata, %{entry_hash: map.entry_hash, entry_height: entry.header.height, status: status})
  end

  # Validator
  def is_validator(pk \\ nil, db_opts \\ %{}) do
    pks = if pk do [pk] else
      Application.fetch_env!(:ama, :keys_all_pks)
    end
    validators = validators_for_height(height()+1, db_opts)
    delta = validators -- pks
    length(validators) != length(delta)
  end

  def validators_for_height(height, db_opts \\ %{}) do
    opts = db_handle(db_opts, :contractstate, %{})
    cond do
      height in 3195570..3195575 and !Application.fetch_env!(:ama, :testnet) ->
        RocksDB.get("bic:epoch:validators:height:000000319557", opts)
        |> RDB.vecpak_decode()
      true ->
        {_, value} = RocksDB.get_prev_or_first("bic:epoch:validators:height:", pad_integer(height), opts)
        RDB.vecpak_decode(value)
    end
  end

  def validators_last_change_height(height, db_opts \\ %{}) do
    opts = db_handle(db_opts, :contractstate, %{})
    {key, _value} = RocksDB.get_prev_or_first("bic:epoch:validators:height:", pad_integer(height), opts)
    :erlang.binary_to_integer(key)
  end

  def validators_for_hash(hash, db_opts \\ %{}) do
    entry = DB.Entry.by_hash(hash)
    if entry do validators_for_height(entry.header.height, db_opts) end
  end

  def validators_for_height_my(height, db_opts \\ %{}) do
    validators = validators_for_height(height, db_opts)
    Application.fetch_env!(:ama, :keys)
    |> Enum.filter(& &1.pk in validators)
    |> Enum.map(& &1.pk)
  end

  def validator_for_height(height, db_opts \\ %{}) do
    validators = validators_for_height(height, db_opts)
    case validators do
      [] -> nil
      _ -> Enum.at(validators, rem(height, length(validators)))
    end
  end

  def validator_for_height_current(db_opts \\ %{}) do
    validator_for_height(height(db_opts), db_opts)
  end

  def validator_for_height_next(db_opts \\ %{}) do
    validator_for_height(height(db_opts) + 1, db_opts)
  end

  def validators_removed(epoch, db_opts \\ %{}) do
    vstart = validators_for_height(epoch * 100_000, db_opts)
    vend = validators_for_height(epoch * 100_000 + 99_999, db_opts)
    vstart -- vend
  end

  #Rewind
  def rewind(target_hash) do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)
    in_chain = DB.Entry.in_chain(target_hash, %{rtx: rtx})
    tip_entry = DB.Chain.tip_entry(%{rtx: rtx})

    target_hash_entry = DB.Entry.by_hash(target_hash, %{rtx: rtx})
    rooted_height = DB.Chain.rooted_height(%{rtx: rtx})

    cond do
      !in_chain or tip_entry.hash == target_hash ->
        RocksDB.transaction_rollback(rtx)
        false
      target_hash_entry.header.height < rooted_height ->
        IO.inspect "cannot rewind finalized entry"
        RocksDB.transaction_rollback(rtx)
        false
      true ->
        rewind_1(tip_entry, target_hash, rtx)
        RocksDB.put("temporal_tip", target_hash, %{rtx: rtx, cf: cf.sysconf})
        :ok = RocksDB.transaction_commit(rtx)
        true
      end
  end
  defp rewind_1(current_entry, target_hash, rtx) do
    m_rev = DB.Entry.muts_rev(current_entry.hash, %{rtx: rtx})
    revert_muts(m_rev, %{rtx: rtx})

    # revert mmr
    case DB.MMR.snapshot_for(current_entry.hash, %{rtx: rtx}) do
      nil  -> raise "rewind: missing MMR snapshot for entry #{Base58.encode(current_entry.hash)} (height #{current_entry.header.height}); cannot restore accumulator"
      prev -> DB.MMR.save(prev, %{rtx: rtx})
    end

    DB.Entry.delete_UNSAFE(current_entry.hash, %{rtx: rtx})
    prev_hash = current_entry.header.prev_hash
    if prev_hash == target_hash do
      :ok
    else
      rewind_1(DB.Entry.by_hash(prev_hash, %{rtx: rtx}), target_hash, rtx)
    end
  end

  def revert_muts(m_rev, db_opts = %{rtx: _}) do
    %{cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    Enum.reverse(m_rev)
    |> Enum.each(fn(mut)->
      op = :"#{mut.op}"
      cf_table = case mut.table do
        "contractstate" -> cf.contractstate
        "contractstate_tree" -> cf.contractstate_tree
        "contractstate_tree_hbsmt" -> cf.contractstate_tree_hbsmt
      end
      case op do
        :put ->
          RocksDB.put(mut.key, mut.value, %{rtx: db_opts.rtx, cf: cf_table})
        :delete ->
          RocksDB.delete(mut.key, %{rtx: db_opts.rtx, cf: cf_table})
        :clear_bit ->
          old_value = RocksDB.get(mut.key, %{rtx: db_opts.rtx, cf: cf_table})
          << left::size(mut.value), _old_bit::size(1), right::bitstring >> = old_value
          new_value = << left::size(mut.value), 0::size(1), right::bitstring >>
          RocksDB.put(mut.key, new_value, %{rtx: db_opts.rtx, cf: cf_table})
      end
    end)
  end
end
