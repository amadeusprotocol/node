defmodule DB.Attestation do
  import DB.API
  #a validator can attest arbitrary mutations_hashes: each may appear in at most
  #this many variants of one entry, so its junk never crowds out a variant
  #started by another validator
  @variants_per_validator 3

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

  def quorum?(hash, muts_hash) do
    case consensus(hash, muts_hash) do
      nil -> false
      c -> BLS12AggSig.quorum?(c.aggsig)
    end
  end

  def set_consensus(consensus, db_opts \\ %{}) do
    entry = DB.Entry.by_hash(consensus.entry_hash, db_opts)
    if entry do
      set = DB.Chain.validator_set_for_height(Entry.height(entry), db_opts)
      case BLS12AggSig.validate(consensus.aggsig, set) do
        {:ok, _} -> set_validated_consensus(consensus, db_opts)
        error -> error
      end
    else
      {:error, :invalid_entry}
    end
  end

  defp set_validated_consensus(consensus, db_opts) do
    score = BLS12AggSig.score(consensus.aggsig)

    old_consensus = consensus(consensus.entry_hash, consensus.mutations_hash, db_opts)
    old_score = if old_consensus do BLS12AggSig.score(old_consensus.aggsig) else 0.0 end

    cond do
      BLS12AggSig.signer_count(consensus.aggsig) == 0 -> {:error, :consensus_variant_limit}
      score <= old_score -> :ok
      #a quorum variant always gets in
      BLS12AggSig.quorum?(consensus.aggsig) ->
        put_consensus(consensus, db_opts)
      signer_variant_limit?(consensus, old_consensus, db_opts) ->
        {:error, :consensus_variant_limit}
      true ->
        put_consensus(consensus, db_opts)
    end
  end

  defp put_consensus(consensus, db_opts) do
    RocksDB.put("consensus:#{consensus.entry_hash}:#{consensus.mutations_hash}", RDB.vecpak_encode(consensus), db_handle(db_opts, :attestation, %{}))
  end

  #only signers this write adds are checked, so an existing variant keeps growing;
  #a variant with no signer in its mask is never stored
  defp signer_variant_limit?(consensus, old_consensus, db_opts) do
    added = signed_indexes(consensus.aggsig) -- if(old_consensus, do: signed_indexes(old_consensus.aggsig), else: [])
    others = consensuses(consensus.entry_hash, db_opts)
    |> Enum.reject(& &1.mutations_hash == consensus.mutations_hash)
    |> Enum.map(& signed_indexes(&1.aggsig))
    added == [] or Enum.any?(added, fn idx -> Enum.count(others, & idx in &1) >= @variants_per_validator end)
  end

  #padding bits are zero (validated), so every set bit is a signer
  defp signed_indexes(%{mask: mask}), do: for({1, i} <- Enum.with_index(for <<b::1 <- mask>>, do: b), do: i)

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
      score = BLS12AggSig.score(consensus.aggsig)
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



  def put(attestation, height, db_opts \\ %{}) do
    a = attestation
    a_packed = Attestation.pack_for_db(attestation)
    RocksDB.put("attestation:#{pad_integer(height)}:#{a.entry_hash}:#{a.signer}:#{a.mutations_hash}", a_packed, db_handle(db_opts, :attestation, %{}))
  end

  #[attestation]
 # attestation:{hash}:{signer}:{muthash} attestation
  #attestation_agg:{hash}:{muthash} consensus

end
