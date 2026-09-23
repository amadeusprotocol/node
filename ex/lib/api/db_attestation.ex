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

  def set_consensus(consensus, db_opts \\ %{}) do
    score = consensus.aggsig.mask_set_size / consensus.aggsig.mask_size

    old_consensus = consensus(consensus.entry_hash, consensus.mutations_hash, db_opts)
    old_score = if old_consensus do old_consensus.aggsig.mask_set_size / old_consensus.aggsig.mask_size else 0.0 end

    cond do
      score <= old_score -> :ok
      #a quorum variant always gets in
      BLS12AggSig.quorum?(consensus.aggsig.mask_set_size, consensus.aggsig.mask_size) ->
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

  defp signed_indexes(%{mask: mask, mask_size: size}) when is_integer(size) and size > 0 do
    BLS12AggSig.unmask_trainers(Enum.to_list(0..(size - 1)), mask, size)
  end
  defp signed_indexes(_aggsig), do: []

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
