defmodule Consensus do
    _ = """
    consensus
      %{
        mutations_hash: <<215, 178, 135, 49, 141, 108, 154, 141, 105, 41, 234, 36,
          222, 56, 0, 124, 63, 25, 150, 225, 37, 216, 254, 73, 65, 240, 8, 33, 179,
          137, 99, 137>>,
        entry_hash: <<0, 0, 1, 33, 82, 24, 33, 251, 157, 137, 149, 20, 44, 42, 139,
          162, 226, 19, 228, 5, 44, 177, 156, 39, 199, 30, 4, 131, 143, 137, 87, 5>>,
        aggsig: %{
          mask: <<255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 224>>,
          aggsig: <<177, 1, 30, 184, 160, 151, 62, 89, 92, 237, 190, 215, 51, 33, 49,
            140, 240, 33, 142, 33, 244, 90, 254, 143, 172, 251, 162, 236, 87, 98, 40,
            217, 87, 117, 211, 197, 168, 234, 16, 79, 24, 232, 205, 37, 174, 159, 192,
            22, 13, 17, 25, 243, 85, 159, 182, 191, 161, 77, 48, 94, 93, 94, 255, 140,
            48, 156, 86, 53, 176, 18, 168, 20, 57, 96, 167, 185, 26, 116, 149, 185,
            87, 1, 20, 253, 17, 250, 131, 223, 82, 161, 120, 123, 35, 112, 255, 75>>,
          mask_size: 99,
          mask_set_size: 99
        }
      }

      entry_hash
      root_blocks
      root_contractstate
      root_receipts
    """

  def validate_vs_chain(c) when is_map(c) do
    entry = DB.Entry.by_hash(c[:entry_hash])

    cond do
      !entry -> %{error: :invalid_entry}
      entry.header.height > DB.Chain.height() -> %{error: :too_far_in_future}
      true -> validate_for_entry(c, entry)
    end
  end

  def validate_vs_chain(_), do: %{error: :invalid_consensus}

  # Validate a quorum certificate carried alongside an advertised entry header.
  # Unlike validate_vs_chain/1 this does not require that entry to be stored yet.
  def validate_for_entry(c, entry) do
    try do
      if !is_binary(c[:entry_hash]) or byte_size(c.entry_hash) != 32,
        do: throw(%{error: :invalid_entry_hash})

      if !is_binary(c[:mutations_hash]) or byte_size(c.mutations_hash) != 32,
        do: throw(%{error: :invalid_mutations_hash})

      if !is_map(entry) or !is_map(entry[:header]), do: throw(%{error: :invalid_entry})

      if Entry.header_hash(entry.header) != c.entry_hash,
        do: throw(%{error: :entry_hash_mismatch})

      to_sign = <<c.entry_hash::binary, c.mutations_hash::binary>>

      validators = DB.Chain.validators_for_height(Entry.height(entry))
      if validators == [], do: throw(%{error: :empty_validator_set})

      if !is_integer(c.aggsig.mask_size) or c.aggsig.mask_size <= 0,
        do: throw(%{error: :mask_size_not_integer})

      if !is_integer(c.aggsig.mask_set_size) or c.aggsig.mask_set_size < 0 or
           c.aggsig.mask_set_size > c.aggsig.mask_size,
         do: throw(%{error: :invalid_mask_set_size})

      if length(validators) != c.aggsig.mask_size, do: throw(%{error: :validators_ne_mask_size})

      case BLS12AggSig.validate_mask(c.aggsig.mask, c.aggsig.mask_size) do
        :ok -> :ok
        {:error, error} -> throw(%{error: error})
      end

      validators_signed =
        BLS12AggSig.unmask_trainers(validators, c.aggsig.mask, c.aggsig.mask_size)

      if length(validators_signed) != c.aggsig.mask_set_size,
        do: throw(%{error: :validators_signed_ne_mask_set_size})

      # Consensus objects imported from peers must already carry quorum. Raw
      # single-validator attestations use the attestation path and are safely
      # aggregated locally. Do every mask/quorum check before expensive BLS.
      if !BLS12AggSig.quorum?(length(validators_signed), length(validators)),
        do: throw(%{error: :insufficient_quorum})

      aggpk = BlsEx.aggregate_public_keys!(validators_signed)

      if !BlsEx.verify?(aggpk, c.aggsig.aggsig, to_sign, BLS12AggSig.dst_att()),
        do: throw(%{error: :invalid_signature})

      %{error: :ok}
    catch
      :throw, r ->
        r

      e, r ->
        IO.inspect({Consensus, :validate, e, r, __STACKTRACE__}, limit: 111_111)
        %{error: :unknown}
    end
  end
end
