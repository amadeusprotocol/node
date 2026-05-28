defmodule DB.Entry do
  import DB.API

  def by_hash(hash, db_opts \\ %{}) do
    RocksDB.get(hash, db_handle(db_opts, :entry, %{}))
    |> Entry.unpack_from_db()
  end

  def fix_entry(hash, db_opts \\ %{}) do
    e = RocksDB.get(hash, db_handle(db_opts, :entry, %{}))
    |> Entry.unpack_from_db()
    if is_binary(e.header_unpacked) do
      if e[:mask] do IO.inspect(e, limit: 11111111); throw %{error: :has_mask} end
      entry = Map.put(e, :header, :erlang.binary_to_term(e.header_unpacked))
      entry = Map.put(e, :header_unpacked, :erlang.binary_to_term(e.header_unpacked))
      entry_packed = Entry.pack_for_db(entry)
      RocksDB.put(entry.hash, entry_packed, db_handle(db_opts, :entry, %{}))
    end
  end

  def by_height(height, db_opts \\ %{}) do
    RocksDB.get_prefix("by_height:#{pad_integer(height)}:", db_handle(db_opts, :entry_meta, %{}))
    |> Enum.map(& by_hash(elem(&1,0), db_opts) )
  end

  def by_height_return_hashes(height, db_opts \\ %{}) do
    RocksDB.get_prefix("by_height:#{pad_integer(height)}:", db_handle(db_opts, :entry_meta, %{}))
    |> Enum.map(& elem(&1,0))
  end

  def by_height_in_main_chain(height, db_opts \\ %{}) do
    RocksDB.get("by_height_in_main_chain:#{pad_integer(height)}", db_handle(db_opts, :entry_meta, %{}))
  end

  def seentime(hash, db_opts \\ %{}) do
    RocksDB.get("entry:#{hash}:seentime", db_handle(db_opts, :entry_meta, %{to_integer: true}))
  end

  def muts_hash(hash, db_opts \\ %{}) do
    RocksDB.get("entry:#{hash}:muts_hash", db_handle(db_opts, :entry_meta, %{}))
  end

  def prev(hash, db_opts \\ %{}) do
    RocksDB.get("entry:#{hash}:prev", db_handle(db_opts, :entry_meta, %{}))
  end

  def next(hash, db_opts \\ %{}) do
    RocksDB.get("entry:#{hash}:next", db_handle(db_opts, :entry_meta, %{}))
  end

  def root_receipts(hash, db_opts \\ %{}) do
    RocksDB.get("entry:#{hash}:root_receipts", db_handle(db_opts, :entry_meta, %{}))
  end

  def root_contractstate(hash, db_opts \\ %{}) do
    RocksDB.get("entry:#{hash}:root_contractstate", db_handle(db_opts, :entry_meta, %{}))
  end

  def in_chain(hash, db_opts \\ %{}) do
    !!RocksDB.get("entry:#{hash}:in_chain", db_handle(db_opts, :entry_meta, %{}))
  end

  def muts(hash, db_opts \\ %{}) do
    RocksDB.get("entry:#{hash}:muts", db_handle(db_opts, :entry_meta, %{}))
    |> RDB.vecpak_decode()
  end

  def muts_rev(hash, db_opts \\ %{}) do
    RocksDB.get("entry:#{hash}:muts_rev", db_handle(db_opts, :entry_meta, %{}))
    |> RDB.vecpak_decode()
  end

  def insert(entry, db_opts \\ %{}) when is_map(entry) do
    db_opts = if db_opts[:rtx] do db_opts else
      %{db: db, cf: _cf} = :persistent_term.get({:rocksdb, Fabric})
      rtx = RocksDB.transaction(db)
      db_opts = Map.put(db_opts, :rtx, rtx)
      Map.put(db_opts, :rtx_commit, true)
    end

    entry_packed = Entry.pack_for_db(entry)
    if !by_hash(entry.hash, db_opts) do
      RocksDB.put(entry.hash, entry_packed, db_handle(db_opts, :entry, %{}))
      RocksDB.put("by_height:#{pad_integer(entry.header.height)}:#{entry.hash}", entry.hash, db_handle(db_opts, :entry_meta, %{}))
      RocksDB.put("entry:#{entry.hash}:seentime", :os.system_time(1000), db_handle(db_opts, :entry_meta, %{to_integer: true}))
    end

    db_opts[:rtx_commit] && RocksDB.transaction_commit(db_opts.rtx)
  end

  def apply_into_main_chain(entry, muts_hash, muts_rev, receipts, root_receipts, root_contractstate, db_opts = %{rtx: _}) do
    prev_mmr = DB.MMR.load_or_empty(db_opts)
    DB.MMR.snapshot_before(entry.hash, prev_mmr, db_opts)
    new_mmr = MMR.append(prev_mmr, entry.hash)
    DB.MMR.save(new_mmr, db_opts)

    # IO.puts "MMR h=#{entry.header.height} root_chain=#{Base.encode16(MMR.root_chain(DB.MMR.chain_id(), new_mmr), case: :lower)}"

    entry_packed = Entry.pack_for_db(entry)
    RocksDB.put(entry.hash, entry_packed, db_handle(db_opts, :entry, %{}))
    RocksDB.put("by_height:#{pad_integer(entry.header.height)}:#{entry.hash}", entry.hash, db_handle(db_opts, :entry_meta, %{}))
    RocksDB.put("by_height_in_main_chain:#{pad_integer(entry.header.height)}", entry.hash, db_handle(db_opts, :entry_meta, %{}))
    #RocksDB.put("entry:#{entry.hash}:seentime", :os.system_time(1000), db_handle(db_opts, :entry_meta, %{to_integer: true}))
    RocksDB.put("entry:#{entry.hash}:prev", entry.header.prev_hash, db_handle(db_opts, :entry_meta, %{}))
    RocksDB.put("entry:#{entry.header.prev_hash}:next", entry.hash, db_handle(db_opts, :entry_meta, %{}))
    RocksDB.put("entry:#{entry.hash}:in_chain", "", db_handle(db_opts, :entry_meta, %{}))
    RocksDB.put("entry:#{entry.hash}:muts_hash", muts_hash, db_handle(db_opts, :entry_meta, %{}))
    RocksDB.put("entry:#{entry.hash}:muts_rev", RDB.vecpak_encode(muts_rev), db_handle(db_opts, :entry_meta, %{}))
    RocksDB.put("entry:#{entry.hash}:root_receipts", root_receipts, db_handle(db_opts, :entry_meta, %{}))
    RocksDB.put("entry:#{entry.hash}:root_contractstate", root_contractstate, db_handle(db_opts, :entry_meta, %{}))

    #Build hashfilter
    tx_filters = RDB.build_tx_hashfilters(entry.txs)
    Enum.each(tx_filters, fn {key, hash} ->
      RocksDB.put(key, hash, db_handle(db_opts, :tx_filter, %{}))
    end)

    #Count tx
    old_cnt = RocksDB.get("tx_count", db_handle(db_opts, :sysconf, %{})) || "0"
    new_cnt = :erlang.binary_to_integer(old_cnt) + length(entry.txs)
    RocksDB.put("tx_count", :erlang.integer_to_binary(new_cnt), db_handle(db_opts, :sysconf, %{}))

    receipts_by_txid = Map.new(receipts, fn r -> {r.txid, Map.drop(r, [:txid])} end)
    Enum.each(entry.txs, fn(txu)->
      receipt = Map.fetch!(receipts_by_txid, txu.hash)
      case :binary.match(entry_packed, TX.pack(txu)) do
          {index_start, index_size} ->
            tx_ptr = %{entry_hash: entry.hash, receipt: receipt, index_start: index_start, index_size: index_size}
            |> RDB.vecpak_encode()
            RocksDB.put(txu.hash, tx_ptr, db_handle(db_opts, :tx, %{}))
        end
    end)
  end

  def apply_into_main_chain_muts(hash, muts, db_opts = %{rtx: _}) do
    RocksDB.put("entry:#{hash}:muts", RDB.vecpak_encode(muts), db_handle(db_opts, :entry_meta, %{}))
  end

  def delete_UNSAFE(_a, _db_opts \\ %{})
  def delete_UNSAFE(nil, _db_opts) do nil end
  def delete_UNSAFE(hash, db_opts) when is_binary(hash) do
    entry = by_hash(hash)
    delete_UNSAFE(entry, db_opts)
  end
  def delete_UNSAFE(entry, db_opts = %{rtx: _}) when is_map(entry) do
    hash = entry.hash

    RocksDB.delete(hash, db_handle(db_opts, :entry, %{}))

    height_padded = pad_integer(entry.header.height)
    main_chain_hash = RocksDB.get("by_height_in_main_chain:#{height_padded}", db_handle(db_opts, :entry_meta, %{}))
    if hash == main_chain_hash do
      RocksDB.delete("by_height_in_main_chain:#{height_padded}", db_handle(db_opts, :entry_meta, %{}))
      RocksDB.delete("entry:#{entry.header.prev_hash}:next", db_handle(db_opts, :entry_meta, %{}))
    end
    RocksDB.delete("by_height:#{height_padded}:#{hash}", db_handle(db_opts, :entry_meta, %{}))
    RocksDB.delete("entry:#{hash}:seentime", db_handle(db_opts, :entry_meta, %{}))
    RocksDB.delete("entry:#{hash}:muts_hash", db_handle(db_opts, :entry_meta, %{}))
    RocksDB.delete("entry:#{hash}:prev", db_handle(db_opts, :entry_meta, %{}))
    RocksDB.delete("entry:#{hash}:next", db_handle(db_opts, :entry_meta, %{}))
    RocksDB.delete("entry:#{hash}:in_chain", db_handle(db_opts, :entry_meta, %{}))
    RocksDB.delete("entry:#{hash}:muts", db_handle(db_opts, :entry_meta, %{}))
    RocksDB.delete("entry:#{hash}:muts_rev", db_handle(db_opts, :entry_meta, %{}))
    RocksDB.delete("entry:#{hash}:root_receipts", db_handle(db_opts, :entry_meta, %{}))
    RocksDB.delete("entry:#{hash}:root_contractstate", db_handle(db_opts, :entry_meta, %{}))
    RocksDB.delete("entry:#{hash}:mmr_peaks_before", db_handle(db_opts, :entry_meta, %{}))
    RocksDB.delete_prefix("consensus:#{hash}:", db_handle(db_opts, :attestation, %{}))
    RocksDB.delete_prefix("attestation:#{height_padded}:#{hash}:", db_handle(db_opts, :attestation, %{}))

    #Delete hashfilter
    tx_filters = RDB.build_tx_hashfilters(entry.txs)
    Enum.each(tx_filters, fn {key, _hash} ->
      RocksDB.delete(key, db_handle(db_opts, :tx_filter, %{}))
    end)

    #Decrement tx
    old_cnt = RocksDB.get("tx_count", db_handle(db_opts, :sysconf, %{})) || "0"
    new_cnt = :erlang.binary_to_integer(old_cnt) - length(entry.txs)
    RocksDB.put("tx_count", :erlang.integer_to_binary(new_cnt), db_handle(db_opts, :sysconf, %{}))

    Enum.each(entry.txs, fn(txu)->
        RocksDB.delete(txu.hash, db_handle(db_opts, :tx, %{}))
    end)
  end

  def build_filter_hashes() do
    rebuilt_up_to = RocksDB.get("filter_hashes_rebuilt_up_to", db_handle(%{}, :sysconf, %{})) || EntryGenesis.get().hash
    entry = by_hash(rebuilt_up_to)
    if rem(entry.header.height, 10_000) == 0 do
      IO.inspect {:rebuilt_filter_hashes_up_to, entry.header.height}
    end
    txs = entry.txs
    txs = Enum.map(txs, fn(txu)->
      txu = if !is_binary(txu) do txu else
        txu = VanillaSer.decode!(txu)
        tx = VanillaSer.decode!(txu.tx_encoded)
        Map.put(txu, :tx, tx)
      end
      action = TX.action(txu)
      args = case action.args do
        [n|t] when is_integer(n) -> [:erlang.integer_to_binary(n) | t]
        args -> args
      end
      args = case action.args do
        [a,b|t] when is_binary(b) and byte_size(b) == 48 -> [b,a] ++ t
        args -> args
      end

      txu = put_in(txu, [:tx, :action], action)
      put_in(txu, [:tx, :action, :args], args)
    end)

    tx_filters = RDB.build_tx_hashfilters(txs)
    Enum.each(tx_filters, fn {key, hash} ->
      RocksDB.put(key, hash, db_handle(%{}, :tx_filter, %{}))
    end)

    n = next(rebuilt_up_to)
    if n do
      RocksDB.put("filter_hashes_rebuilt_up_to", n, db_handle(%{}, :sysconf, %{}))
    end
  end
end
