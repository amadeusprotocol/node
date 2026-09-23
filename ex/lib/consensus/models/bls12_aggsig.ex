defmodule BLS12AggSig do
    @doc """
    aggsig {
        aggsig: <>,
        mask: <>,
        mask_size: 0,
        mask_set_size: 0,
    }
    """

    @dst "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
    @dst_pop "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
    @dst_att "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ATTESTATION_"
    @dst_entry "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ENTRY_"
    @dst_vrf "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_VRF_"
    @dst_tx "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_TX_"
    @dst_motion "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_MOTION_"
    @dst_node "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NODE_"
    @dst_anr "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ANR_"
    @dst_anr_challenge "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ANRCHALLENGE_"
    @dst_bundle "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_STATE_BUNDLE_"

    def dst(), do: @dst
    def dst_pop(), do: @dst_pop
    def dst_att(), do: @dst_att
    def dst_entry(), do: @dst_entry
    def dst_vrf(), do: @dst_vrf
    def dst_tx(), do: @dst_tx
    def dst_motion(), do: @dst_motion
    def dst_node(), do: @dst_node
    def dst_anr(), do: @dst_anr
    def dst_anr_challenge(), do: @dst_anr_challenge
    def dst_bundle(), do: @dst_bundle

    def new(trainers, pk, signature) do
        index_of_trainer = Util.index_of(trainers, pk)

        mask = <<0::size(length(trainers))>>
        mask = Util.set_bit(mask, index_of_trainer)

        %{mask: mask, aggsig: signature}
    end

    def new_padded(mask_size) do
        mask = Util.pad_bitstring_to_bytes(<<0::size(mask_size)>>)
        %{mask: mask, mask_size: mask_size, mask_set_size: 0}
    end

    def add(m = %{mask: mask, aggsig: aggsig}, trainers, pk, signature) do
        index_of_trainer = Util.index_of(trainers, pk)

        if Util.get_bit(mask, index_of_trainer) do m else
            mask = Util.set_bit(mask, index_of_trainer)
            aggsig = BlsEx.aggregate_signatures!([aggsig, signature])
            %{mask: mask, aggsig: aggsig}
        end
    end

    def add_padded(m = %{mask: mask, mask_size: mask_size}, signers, pk, signature) do
        index_of_signer = Util.index_of(signers, pk)

        if Util.get_bit(mask, index_of_signer) do m else
            mask = Util.set_bit(mask, index_of_signer)
            case m[:aggsig] do
              nil -> %{mask: mask, mask_size: mask_size, mask_set_size: Util.popcnt(mask), aggsig: signature}
              aggsig ->
                aggsig = BlsEx.aggregate_signatures!([aggsig, signature])
                %{mask: mask, mask_size: mask_size, mask_set_size: Util.popcnt(mask), aggsig: aggsig}
            end
        end
    end

    def validate_mask(mask, mask_size) do
        cond do
            !is_integer(mask_size) -> {:error, :mask_size_not_integer}
            mask_size < 0 -> {:error, :mask_size_negative}
            !is_bitstring(mask) -> {:error, :mask_not_bitstring}
            !is_binary(mask) -> {:error, :mask_not_byte_aligned}
            byte_size(mask) != div(mask_size + 7, 8) -> {:error, :mask_wrong_size}
            !padding_bits_zero?(mask, mask_size) -> {:error, :mask_nonzero_padding}
            true -> :ok
        end
    end

    def quorum?(mask_set_size, mask_size)
        when is_integer(mask_set_size) and is_integer(mask_size) and
               mask_set_size >= 0 and mask_size > 0 and mask_set_size <= mask_size do
        mask_set_size * 100 >= mask_size * 67
    end
    def quorum?(_mask_set_size, _mask_size), do: false

    def unmask_trainers(trainers, mask, mask_size)
        when is_list(trainers) and is_bitstring(mask) and is_integer(mask_size) and mask_size > 0 do
        Enum.zip(Enum.take(trainers, mask_size), for(<<b::1 <- mask>>, do: b))
        |> Enum.flat_map(fn {pk, 1} -> [pk]; _ -> [] end)
    end
    def unmask_trainers(_trainers, _mask, _mask_size), do: []

    def score([], _mask, _mask_size), do: 0.0
    def score(trainers, mask, mask_size) do
        trainers_signed = unmask_trainers(trainers, mask, mask_size)
        length(trainers_signed) / length(trainers)
    end

    def aggregate(total_signer_list, signer_signature_list) do
      signer_signature_list = List.wrap(signer_signature_list)
      aggsig = BLS12AggSig.new_padded(length(total_signer_list))
      Enum.reduce(signer_signature_list, aggsig, fn(signer_signature, aggsig)->
        BLS12AggSig.add_padded(aggsig, total_signer_list, signer_signature.signer, signer_signature.signature)
      end)
    end

    defp padding_bits_zero?(mask, mask_size) do
        padding_size = bit_size(mask) - mask_size

        case padding_size do
            0 -> true
            _ ->
                <<_::size(^mask_size), padding::size(^padding_size)>> = mask
                padding == 0
        end
    end
end
