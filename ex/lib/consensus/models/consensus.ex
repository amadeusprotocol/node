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

    def validate_vs_chain(c) do
        try do
        to_sign = <<c.entry_hash::binary, c.mutations_hash::binary>>

        entry = DB.Entry.by_hash(c.entry_hash)
        if !entry, do: throw(%{error: :invalid_entry})
        if entry.header.height > DB.Chain.height(), do: throw(%{error: :too_far_in_future})

        validators = DB.Chain.validators_for_height(Entry.height(entry))
        if !is_integer(c.aggsig.mask_size), do: throw(%{error: :mask_size_not_integer})
        if !is_bitstring(c.aggsig.mask), do: throw(%{error: :mask_not_bitstring})
        if length(validators) != c.aggsig.mask_size, do: throw(%{error: :validators_ne_mask_size})
        if bit_size(c.aggsig.mask) < c.aggsig.mask_size, do: throw(%{error: :mask_too_short})

        validators_signed = BLS12AggSig.unmask_trainers(validators, c.aggsig.mask, c.aggsig.mask_size)
        aggpk = BlsEx.aggregate_public_keys!(validators_signed)
        if !BlsEx.verify?(aggpk, c.aggsig.aggsig, to_sign, BLS12AggSig.dst_att()), do: throw(%{error: :invalid_signature})

        if length(validators_signed) != c.aggsig.mask_set_size, do: throw(%{error: :validators_signed_ne_mask_set_size})

        %{error: :ok}
        catch
            :throw,r -> r
            e,r -> IO.inspect({Consensus, :validate, e, r, __STACKTRACE__}, limit: 111111); %{error: :unknown}
        end
    end
end
