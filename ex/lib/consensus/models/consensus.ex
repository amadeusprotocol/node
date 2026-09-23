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

  @max_reconstruct_removals 1

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

      height = Entry.height(entry)
      validators = DB.Chain.validators_for_height(height)
      if validators == [], do: throw(%{error: :empty_validator_set})

      if !is_integer(c.aggsig.mask_size) or c.aggsig.mask_size <= 0,
        do: throw(%{error: :mask_size_not_integer})

      if !is_integer(c.aggsig.mask_set_size) or c.aggsig.mask_set_size < 0 or
           c.aggsig.mask_set_size > c.aggsig.mask_size,
         do: throw(%{error: :invalid_mask_set_size})

      case BLS12AggSig.validate_mask(c.aggsig.mask, c.aggsig.mask_size) do
        :ok -> :ok
        {:error, error} -> throw(%{error: error})
      end

      validators = validators -- removed_cached(height)
      diff = length(validators) - c.aggsig.mask_size

      result =
        cond do
          diff == 0 -> verify_quorum_signature(validators, c, to_sign)
          diff >= 1 and diff <= @max_reconstruct_removals ->
            reconstruct_and_verify(validators, c, to_sign, height, diff)
          true -> %{error: :validators_ne_mask_size}
        end

      case result do
        %{error: :ok} -> %{error: :ok}
        err -> throw(err)
      end
    catch
      :throw, r ->
        r

      e, r ->
        IO.inspect({Consensus, :validate, e, r, __STACKTRACE__}, limit: 111_111)
        %{error: :unknown}
    end
  end

  defp verify_quorum_signature(validators, c, to_sign) do
    cond do
      length(validators) != c.aggsig.mask_size ->
        %{error: :validators_ne_mask_size}

      true ->
        signed = BLS12AggSig.unmask_trainers(validators, c.aggsig.mask, c.aggsig.mask_size)

        cond do
          length(signed) != c.aggsig.mask_set_size -> %{error: :validators_signed_ne_mask_set_size}
          !BLS12AggSig.quorum?(length(signed), length(validators)) -> %{error: :insufficient_quorum}
          !BlsEx.verify?(BlsEx.aggregate_public_keys!(signed), c.aggsig.aggsig, to_sign, BLS12AggSig.dst_att()) ->
            %{error: :invalid_signature}
          true -> %{error: :ok}
        end
    end
  end

  defp reconstruct_and_verify(validators, c, to_sign, height, 1) do
    n = length(validators)

    Enum.reduce_while(0..(n - 1), %{error: :validators_ne_mask_size}, fn i, acc ->
      case verify_quorum_signature(List.delete_at(validators, i), c, to_sign) do
        %{error: :ok} ->
          cache_removed(height, Enum.at(validators, i))
          {:halt, %{error: :ok}}

        _ ->
          {:cont, acc}
      end
    end)
  end

  defp removed_cache_key(height), do: {__MODULE__, :removed_mid_epoch, div(height, 100_000)}

  defp removed_cached(height), do: :persistent_term.get(removed_cache_key(height), [])

  defp cache_removed(height, pk) do
    key = removed_cache_key(height)
    removed = :persistent_term.get(key, [])
    unless pk in removed, do: :persistent_term.put(key, [pk | removed])
    :ok
  end
end
