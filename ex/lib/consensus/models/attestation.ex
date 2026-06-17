defmodule Attestation do
    _ = """
    attestation {
        hash: <>,
        entry_hash: <>,
        entry_height: <>,
        mutations_hash: <>,
        root_receipts: <>,
        root_contractstate: <>,
        root_entries: <>,
        signer: <>,
        signature: <entry_hash,mutations_hash>,
    }
    """
    #@fields [:hash, :signature, :attestation, :signer, :entry_hash, :entry_height, :mutations_hash, :root_receipts, :root_contractstate, :root_entries]
    @fields [:entry_hash, :mutations_hash, :signer, :signature]
    @fields_attestation [:signer, :entry_hash, :entry_height, :root_receipts, :root_contractstate, :root_entries]

    def pack_for_db(attestation_unpacked) when is_binary(attestation_unpacked) do attestation_unpacked end
    def pack_for_db(attestation_unpacked) do
      attestation_unpacked
      |> Map.take(@fields)
      |> RDB.vecpak_encode()
    end

    def sign(sk, entry_hash, entry_height, mutations_hash, root_receipts, root_contractstate, root_entries) do
        pk = BlsEx.get_public_key!(sk)
        signature = BlsEx.sign!(sk, <<entry_hash::binary, mutations_hash::binary>>, BLS12AggSig.dst_att())
        %{
            entry_hash: entry_hash,
            mutations_hash: mutations_hash,
            signer: pk,
            signature: signature,
        }
    end

    def validate(a) do
      try do
        a = Map.take(a, @fields)

        if !is_binary(a.entry_hash), do: throw(%{error: :entry_hash_not_binary})
        if byte_size(a.entry_hash) != 32, do: throw(%{error: :entry_hash_not_256_bits})
        if !is_binary(a.mutations_hash), do: throw(%{error: :mutations_hash_not_binary})
        if byte_size(a.mutations_hash) != 32, do: throw(%{error: :mutations_hash_not_256_bits})
        if !is_binary(a.signer), do: throw(%{error: :signer_not_binary})
        if byte_size(a.signer) != 48, do: throw(%{error: :signer_not_48_bytes})

        claim = <<a.entry_hash::binary, a.mutations_hash::binary>>
        if !BlsEx.verify?(a.signer, a.signature, claim, BLS12AggSig.dst_att()), do: throw(%{error: :invalid_signature})

        %{error: :ok, attestation: a}
      catch
          :throw,r -> r
          e,r -> IO.inspect {Attestation, :validate, e, r}; %{error: :unknown}
      end
    end

    def validate_vs_chain(a) do
      entry = DB.Entry.by_hash(a.entry_hash)
      res = validate(a)
      cond do
        res.error != :ok -> res
        !entry -> %{error: :entry_dne}
        Entry.height(entry) > DB.Chain.height() -> %{error: :ahead_of_localchain}
        a.signer not in DB.Chain.validators_for_height(Entry.height(entry)) -> %{error: :not_validator}
        true -> %{error: :ok}
      end
    end
end
