defmodule DB.Attestation do
  import DB.API
  @variants_per_validator 10

  def consensuses(hash, db_opts \\ %{}) do
    RocksDB.get_prefix("consensus:#{hash}:", db_handle(db_opts, :attestation, %{}))
    |> Enum.map(& RDB.vecpak_decode( elem(&1,1) ))
  end

  def consensus(hash, muts_hash, db_opts \\ %{}) do
    RocksDB.get("consensus:#{hash}:#{muts_hash}", db_handle(db_opts, :attestation, %{}))
    |> case do
      nil -> nil
      value -> RDB.vecpak_decode(value)
    end
  end

  def set_consensus(consensus, db_opts \\ %{}) do
    score = consensus.aggsig.mask_set_size / consensus.aggsig.mask_size

    old_consensus = consensus(consensus.entry_hash, consensus.mutations_hash, db_opts)
    old_score = if old_consensus do old_consensus.aggsig.mask_set_size / old_consensus.aggsig.mask_size else 0.0 end

    cond do
      score <= old_score ->
        :ok

      quorum_consensus?(consensus) ->
        case make_room_for_quorum(consensus, db_opts) do
          :ok -> put_consensus(consensus, db_opts)
          error -> {:error, error}
        end

      old_consensus ->
        case added_signer_variant_limit_error(consensus, old_consensus, db_opts) do
          nil -> put_consensus(consensus, db_opts)
          error -> {:error, error}
        end

      true ->
        case consensus_variant_limit_error(consensus, db_opts) do
          nil -> put_consensus(consensus, db_opts)
          error -> {:error, error}
        end
    end
  end

  defp quorum_consensus?(consensus) do
    count = MapSet.size(MapSet.new(signed_indexes(consensus.aggsig, consensus.aggsig.mask_size)))
    count == consensus.aggsig.mask_set_size and BLS12AggSig.quorum?(count, consensus.aggsig.mask_size)
  end

  # A formed quorum must never be locked out by partial variants. Preserve the
  # same hard caps by removing the lowest-score replaceable variants first.
  defp make_room_for_quorum(candidate, db_opts) do
    case DB.Entry.by_hash(candidate.entry_hash, db_opts) do
      nil ->
        :consensus_variant_limit

      entry ->
        validators = DB.Chain.validators_for_height(Entry.height(entry), db_opts)
        variants =
          consensuses(candidate.entry_hash, db_opts)
          |> Enum.reject(& &1.mutations_hash == candidate.mutations_hash)
          |> Enum.sort_by(&{quorum_consensus?(&1), &1.aggsig.mask_set_size})

        total_limit = length(validators) * @variants_per_validator
        evict_for_quorum(candidate, variants, validators, total_limit, [], db_opts)
    end
  end

  defp evict_for_quorum(candidate, variants, validators, total_limit, evicted, db_opts) do
    if consensus_limits_ok?([candidate | variants], validators, total_limit) do
      Enum.each(evicted, fn variant ->
        RocksDB.delete(
          "consensus:#{variant.entry_hash}:#{variant.mutations_hash}",
          db_handle(db_opts, :attestation, %{})
        )
      end)

      :ok
    else
      case variants do
        [victim | rest] ->
          evict_for_quorum(candidate, rest, validators, total_limit, [victim | evicted], db_opts)

        [] ->
          :consensus_variant_limit
      end
    end
  end

  defp consensus_limits_ok?(variants, validators, total_limit) do
    counts = Enum.reduce(variants, %{}, fn variant, acc ->
      Enum.reduce(signed_indexes(variant.aggsig, length(validators)), acc, fn idx, acc2 ->
        Map.update(acc2, idx, 1, &(&1 + 1))
      end)
    end)

    total_limit > 0 and length(variants) <= total_limit and
      Enum.all?(counts, fn {_idx, count} -> count <= @variants_per_validator end)
  end

  # Bound both total mutation fan-out and each validator's contribution. An
  # existing variant may gain signatures without consuming another total slot,
  # but every newly added signer must still remain below its per-validator cap.
  defp consensus_variant_limit_error(consensus, db_opts) do
    case DB.Entry.by_hash(consensus.entry_hash, db_opts) do
      nil ->
        :consensus_variant_limit

      entry ->
        validators = DB.Chain.validators_for_height(Entry.height(entry), db_opts)
        total_limit = length(validators) * @variants_per_validator
        prefix = "consensus:#{consensus.entry_hash}:"
        variant_count = RocksDB.prefix_count_up_to(prefix, total_limit, db_handle(db_opts, :attestation, %{}))
        cond do
          total_limit == 0 or variant_count >= total_limit ->
            :consensus_variant_limit

          signer_variant_limit_reached?(consensus, validators, db_opts) ->
            :consensus_variant_limit

          true -> nil
        end
    end
  end

  defp added_signer_variant_limit_error(candidate, old, db_opts) do
    case DB.Entry.by_hash(candidate.entry_hash, db_opts) do
      nil -> :consensus_variant_limit
      entry ->
        validators = DB.Chain.validators_for_height(Entry.height(entry), db_opts)
        old_signers = signed_indexes(old.aggsig, length(validators)) |> MapSet.new()
        new_signers = signed_indexes(candidate.aggsig, length(validators)) |> MapSet.new()
        added = MapSet.difference(new_signers, old_signers)
        if signer_indexes_limit_reached?(added, candidate.entry_hash, validators, db_opts),
          do: :consensus_variant_limit,
          else: nil
    end
  end

  defp signer_variant_limit_reached?(candidate, validators, db_opts) do
    candidate_signers = signed_indexes(candidate.aggsig, length(validators)) |> MapSet.new()
    signer_indexes_limit_reached?(candidate_signers, candidate.entry_hash, validators, db_opts)
  end

  defp signer_indexes_limit_reached?(candidate_signers, entry_hash, validators, db_opts) do
    #An empty set is invalid at network validation, but keeping this storage
    #helper cheap also lets total-cap tests avoid repeatedly decoding every row.
    if MapSet.size(candidate_signers) == 0 do
      false
    else
      variants = consensuses(entry_hash, db_opts)
    counts = Enum.reduce(variants, %{}, fn variant, acc ->
      Enum.reduce(signed_indexes(variant.aggsig, length(validators)), acc, fn idx, acc2 ->
        Map.update(acc2, idx, 1, &(&1 + 1))
      end)
    end)
    Enum.any?(candidate_signers, &(Map.get(counts, &1, 0) >= @variants_per_validator))
    end
  end

  defp signed_indexes(aggsig, validator_count) do
    if is_binary(aggsig[:mask]) and aggsig[:mask_size] == validator_count do
      0..(validator_count - 1)
      |> Enum.filter(& Util.get_bit(aggsig.mask, &1))
    else
      []
    end
  end

  defp put_consensus(consensus, db_opts) do
    RocksDB.put(
      "consensus:#{consensus.entry_hash}:#{consensus.mutations_hash}",
      RDB.vecpak_encode(consensus),
      db_handle(db_opts, :attestation, %{})
    )
  end

  def consensuses_by_height(height, db_opts \\ %{}) do
    DB.Entry.by_height_return_hashes(height, db_opts)
    |> Enum.map(fn(hash)->
        DB.Attestation.consensuses(hash, db_opts)
        |> Enum.map(fn %{aggsig: aggsig, mutations_hash: mutations_hash} ->
            %{entry_hash: hash, mutations_hash: mutations_hash, aggsig: aggsig}
        end)
    end)
    |> List.flatten()
  end

  def best_consensus_by_entryhash(hash) do
    consensuses(hash)
    |> Enum.reduce({nil,nil}, fn(consensus, {best_mutshash, best_score}) ->
      score = consensus.aggsig.mask_set_size/consensus.aggsig.mask_size
      cond do
          !best_mutshash -> {consensus.mutations_hash, score}
          score > best_score -> {consensus.mutations_hash, score}
          true -> {best_mutshash, best_score}
      end
    end)
  end

  #Attestations
  def by_height(height, db_opts \\ %{}) do
    RocksDB.get_prefix("attestation:#{pad_integer(height)}:", db_handle(db_opts, :attestation, %{}))
    |> Enum.map(& RDB.vecpak_decode( elem(&1,1) ))
  end

  def by_height_my(height, db_opts \\ %{}) do
    my_validators = DB.Chain.validators_for_height_my(height, db_opts)
    by_height(height, db_opts)
    |> Enum.filter(& &1.signer in my_validators)
  end

  def by_height_by_signer(height, signer, db_opts \\ %{}) do
    RocksDB.get_prefix("attestation:#{pad_integer(height)}:", db_handle(db_opts, :attestation, %{}))
    |> Enum.map(& RDB.vecpak_decode(elem(&1, 1)))
    |> Enum.find(& &1.signer == signer)
  end


  def missing_attestations(height, mask, mask_size, db_opts \\ %{}) do

  end

  def put(attestation, height, db_opts \\ %{}) do
    a = attestation
    a_packed = Attestation.pack_for_db(attestation)
    RocksDB.put("attestation:#{pad_integer(height)}:#{a.entry_hash}:#{a.signer}:#{a.mutations_hash}", a_packed, db_handle(db_opts, :attestation, %{}))
  end

  #def put_or_error(attestation, db_opts \\ %{}) do
  #  a = attestation
  #  height = 0
  #  round = 0

  #  existing = attestations_for_height_by_signer(a.height, a.signer, db_opts)
  #  cond do
  #    length(existing) >= 1 and a not in existing ->
  #      #DB.Slash.record()
  #      %{error: :multiple_vote_cast}
  #    a in existing ->
  #      %{error: :ok}
  #    true ->
  #      RocksDB.put("attestation:#{height}:#{a.entry_hash}:#{a.signer}:#{a.mutations_hash}", Attestation2.pack(a), db_handle(db_opts, :attestation, %{}))
  #      %{error: :ok}
  #  end
  #end

  #[attestation]
 # attestation:{hash}:{signer}:{muthash} attestation
  #attestation_agg:{hash}:{muthash} consensus

end
