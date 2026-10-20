defmodule FabricInbox do
  #landing table for entries, attestations and consensuses off the network.
  #arrival only checks what needs no validator set (structure, hashes, self
  #contained signatures): the set to check against is the one at the item's
  #height, which we may not have applied yet. FabricGen drains it in height
  #order and runs the full checks right before storing/applying, so data for
  #heights far ahead of us never touches RocksDB
  #
  #row: {key, %{value, bytes, vouched, validated_on_parent, verified_roster_hash}}
  #  validated_on_parent: main chain hash at height-1 when the row was verified
  #  and applied (false: not yet). a softfork that replaces it makes the drain
  #  revalidate against the new branch's validators. rows stay until rooted
  #  passes their height
  #key: {height, type, entry_hash, mutations_hash, extra}
  #  type 0 entry, 1 consensus, 2 attestation. extra: signature / aggsig / signer
  #  (a consensus is stored before the attestations of its height aggregate
  #  onto it: the other way round it would replace their aggregate)
  #  (entry hash covers the header only: an unchecked forged copy must not
  #  claim the key of the real one)
  #  unused fields are nil: every key is a 5-tuple, tuples order by size first
  #  attestations/consensuses carry no height: catchup gives the trie height,
  #  gossip the one of its entry at tip+1 here or in RocksDB (else dropped;
  #  catchup refetches). they are retried until they apply
  #vouched: entry signer is in the validator set as we know it at arrival. only
  #a hint for the sync loops (a junk entry must not hide a height we lack)
  #
  #capped at fabric_inbox_max_bytes; when full the highest rows are evicted so
  #heights next to apply always fit. the counter tracks real memory roughly:
  #packed size + @row_overhead per row and per tx

  @entry 0
  @consensus 1
  @attestation 2
  @row_overhead 1024

  def init() do
    :ets.new(FabricInbox, [:ordered_set, :named_table, :public,
      {:write_concurrency, true}, {:read_concurrency, true}, {:decentralized_counters, false}])
    :persistent_term.put({__MODULE__, :bytes}, :atomics.new(1, []))
  end

  defp byte_counter(), do: :persistent_term.get({__MODULE__, :bytes})
  defp max_bytes(), do: Application.fetch_env!(:ama, :fabric_inbox_max_bytes)
  defp chain_rooted_height(), do: DB.Chain.rooted_height() || 0

  #entry hashes held for height; vouched_only skips entries whose signer we
  #could not place in the validator set
  def entry_hashes(height, vouched_only \\ false) do
    row = if vouched_only do %{vouched: true} else :_ end
    :ets.select(FabricInbox, [{{{height, @entry, :"$1", :_, :_}, row}, [], [:"$1"]}])
  end

  #the peer's tip only moves for a signer we know as a validator (as in event_tip)
  #and never from a masked entry: its signature is only checked at drain
  def insert_entry(entry_packed, peer_pk) do
    with {status, %{header: header} = peer_tip} when status in [:ok, :exists] <- insert_entry(entry_packed),
         false <- !!peer_tip[:mask],
         true <- header.signer in (DB.Chain.validators_for_height(header.height) || []) do
      NodeANR.set_tips(peer_pk, nil, %{header: header, hash: peer_tip.hash, sig_error: :ok})
    end
  end

  defp insert_entry(entry_packed) do
    try do
      entry = Entry.unpack_from_net(entry_packed)
      header = entry.header
      entry_hash = Entry.header_hash(header)
      height = header.height
      key = {height, @entry, entry_hash, nil, entry.signature}
      peer_tip = %{header: header, hash: entry_hash, mask: entry[:mask]}
      cond do
        !is_integer(height) -> {:error, :height_not_integer}
        height < chain_rooted_height() -> {:error, :below_rooted}
        :ets.member(FabricInbox, key) or DB.Entry.in_chain(entry_hash) -> {:exists, peer_tip}
        true ->
          case Entry.unpack_and_validate_from_net(entry_packed) do
            %{error: :ok, entry: entry} ->
              bytes = :erlang.external_size(entry) + @row_overhead * (1 + length(entry.txs))
              insert_row(key, entry, bytes, vouched?(entry))
              {:ok, peer_tip}
            %{error: error} -> {:error, error}
          end
      end
    catch
      _, _ -> {:error, :malformed}
    end
  end

  def insert_attestation(attestation, height \\ nil) do
    try do
      height = height || entry_height(attestation.entry_hash)
      key = {height, @attestation, attestation.entry_hash, attestation.mutations_hash, attestation.signer}
      cond do
        !is_integer(height) -> {:error, :entry_unknown}
        height <= chain_rooted_height() -> {:error, :below_rooted}
        :ets.member(FabricInbox, key) -> :exists
        true ->
          case Attestation.validate(attestation) do
            %{error: :ok, attestation: attestation} ->
              insert_row(key, attestation, :erlang.external_size(attestation) + @row_overhead, true)
            %{error: error} -> {:error, error}
          end
      end
    catch
      _, _ -> {:error, :malformed}
    end
  end

  def insert_consensus(consensus, height \\ nil) do
    try do
      aggsig = Map.take(consensus.aggsig, [:mask, :mask_active, :aggsig])
      consensus = %{entry_hash: consensus.entry_hash, mutations_hash: consensus.mutations_hash, aggsig: aggsig}
      %{entry_hash: entry_hash, mutations_hash: mutations_hash} = consensus
      %{mask: mask, aggsig: signature} = aggsig
      height = height || entry_height(entry_hash)
      cond do
        !is_integer(height) -> {:error, :entry_unknown}
        height <= chain_rooted_height() -> {:error, :below_rooted}
        !is_binary(entry_hash) or byte_size(entry_hash) != 32 -> {:error, :entry_hash_not_256_bits}
        !is_binary(mutations_hash) or byte_size(mutations_hash) != 32 -> {:error, :mutations_hash_not_256_bits}
        !is_binary(signature) or byte_size(signature) != 96 -> {:error, :aggsig_not_96_bytes}
        !is_binary(mask) or BLS12AggSig.signer_count(aggsig) == 0 -> {:error, :invalid_mask}
        true ->
          key = {height, @consensus, entry_hash, mutations_hash, aggsig}
          case !:ets.member(FabricInbox, key) and Consensus.verify_signature_vs_epoch_roster(consensus, height) do
            false -> :exists
            :invalid -> {:error, :invalid_signature}
            verified_roster_hash -> insert_row(key, consensus, :erlang.external_size(consensus) + @row_overhead, true, verified_roster_hash)
          end
      end
    catch
      _, _ -> {:error, :malformed}
    end
  end

  defp vouched?(entry) do
    entry.header.signer in (DB.Chain.validators_for_height(entry.header.height) || [])
  end

  #gossip outruns our drain: its entry is often still waiting here at tip+1
  defp entry_height(entry_hash) do
    next_height = DB.Chain.height() + 1
    if :ets.select_count(FabricInbox, [{{{next_height, @entry, entry_hash, :_, :_}, :_}, [], [true]}]) > 0,
      do: next_height, else: DB.Entry.height(entry_hash)
  end

  #insert, then evict from the top until under the cap (maybe the row itself).
  #take/1 hands every row to exactly one process, so bytes are released once
  defp insert_row(key, value, bytes, vouched, verified_roster_hash \\ nil) do
    row = %{value: value, bytes: bytes, vouched: vouched, validated_on_parent: false, verified_roster_hash: verified_roster_hash}
    cond do
      !:ets.insert_new(FabricInbox, {key, row}) -> :exists
      :atomics.add_get(byte_counter(), 1, bytes) > max_bytes() and (evict_highest(); !:ets.member(FabricInbox, key)) -> {:error, :inbox_full}
      true -> :ok
    end
  end

  #:ets.last is the highest height: the furthest from being applied
  defp evict_highest() do
    with true <- :atomics.get(byte_counter(), 1) > max_bytes(),
         highest_key when highest_key != :"$end_of_table" <- :ets.last(FabricInbox) do
      Enum.each(:ets.take(FabricInbox, highest_key), &release_bytes/1)
      evict_highest()
    end
  end

  defp release_bytes({_key, row}), do: :atomics.sub(byte_counter(), 1, row.bytes)

  #FabricGen pulls only what is next: entries for the block to apply
  #(drain_entries) and entries/consensuses/attestations for the block to root
  #(drain_consensus), each checked against the validator set of its height.
  #the rest waits here. a row is redone when the block below it changed
  #(softfork); rows at or below rooted_height go: no softfork can need them

  def drop_rooted(rooted_height) do
    with {height, _, _, _, _} = key when height <= rooted_height <- :ets.first(FabricInbox) do
      Enum.each(:ets.take(FabricInbox, key), &release_bytes/1)
      drop_rooted(rooted_height)
    end
  end

  #entries of the block to apply, on top of parent_hash (the tip)
  def drain_entries(height, parent_hash) do
    pending(height, @entry, parent_hash) |> store_entries()
  end

  #consensuses then attestations of the block to root, on top of parent_hash
  #(the rooted tip). verification in parallel, writes in key order: a consensus
  #is stored before the attestations of its height aggregate onto it
  def drain_consensus(height, parent_hash) do
    #a sibling that arrived after this height was applied: consensus may pick it
    pending(height, @entry, parent_hash) |> store_entries()

    verify_in_parallel(pending(height, @consensus, parent_hash), & Consensus.validate_vs_chain(&1.value, &1.verified_roster_hash) == %{error: :ok})
    |> Enum.each(fn({key, row, parent_hash, valid})->
      valid && (DB.Attestation.set_consensus(row.value); mark_validated(key, row, parent_hash))
    end)

    pending(height, @attestation, parent_hash)
    |> Enum.each(fn({key, row, parent_hash})->
      aggregate_attestation(row.value) == :aggregated && mark_validated(key, row, parent_hash)
    end)
  end

  #rows of height/type not yet validated on parent_hash, without walking the table
  defp pending(height, type, parent_hash) do
    :ets.select(FabricInbox, [{{{height, type, :_, :_, :_}, :_}, [], [:"$_"]}])
    |> Enum.reject(fn({_key, row})-> row.validated_on_parent == parent_hash end)
    |> Enum.map(fn({key, row})-> {key, row, parent_hash} end)
  end

  #entries are done once verified, valid or not
  defp store_entries(pending) do
    verify_in_parallel(pending, & Entry.validate_vs_validators(&1.value) == %{error: :ok})
    |> Enum.each(fn({key, row, parent_hash, valid})->
      valid && DB.Entry.insert(row.value)
      mark_validated(key, row, parent_hash)
    end)
  end

  #verification only, no writes: {key, row, parent_hash, valid}
  defp verify_in_parallel(pending, verify) do
    Task.async_stream(pending, fn({key, row, parent_hash})->
      {key, row, parent_hash, try do verify.(row) catch _, _ -> false end}
    end, ordered: true, timeout: :infinity)
    |> Enum.map(fn({:ok, result})-> result end)
  end

  #update_element: a row evicted meanwhile stays gone
  defp mark_validated(key, row, parent_hash) do
    :ets.update_element(FabricInbox, key, {2, %{row | validated_on_parent: parent_hash}})
  end

  #signature already verified; signer must be a validator of the entry's height
  def aggregate_attestation(attestation) when is_map(attestation) do
    %{db: db} = :persistent_term.get({:rocksdb, Fabric})
    rtx = RocksDB.transaction(db)

    %{entry_hash: entry_hash, mutations_hash: mutations_hash, signer: signer, signature: signature} = attestation
    entry = DB.Entry.by_hash(entry_hash, %{rtx: rtx})
    set = if entry, do: DB.Chain.validator_set_for_height(Entry.height(entry), %{rtx: rtx})
    #add_padded throws on a stored aggsig that no longer matches the set (softfork)
    result = try do
      if entry && set && signer in ValidatorSet.active(set) && entry.header.height <= DB.Chain.height(%{rtx: rtx}) do
        consensus = DB.Attestation.consensus(entry_hash, mutations_hash, %{rtx: rtx}) || %{mutations_hash: mutations_hash, entry_hash: entry_hash}
        aggsig = consensus[:aggsig] || BLS12AggSig.new_padded(set)
        consensus = Map.put(consensus, :aggsig, BLS12AggSig.add_padded(aggsig, set, signer, signature))
        case DB.Attestation.set_consensus(consensus, %{rtx: rtx}) do
          {:error, _} -> nil
          _ -> :aggregated
        end
      end
    catch :throw, _ -> nil
    end
    RocksDB.transaction_commit(rtx)
    result
  end
end
