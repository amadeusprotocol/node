defmodule BLS12AggSig do
    @doc """
    aggsig {
        aggsig: <>,
        mask: <>,
        mask_active: <>,
    }
    """

    @dst "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
    @dst_pop "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
    @dst_att "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ATTESTATION_"
    @dst_entry "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ENTRY_"
    @dst_vrf "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_VRF_"
    @dst_tx "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_TX_"
    #a tx signs only action/signer/nonce (no chain id): a separate testnet domain
    #keeps testnet txs from replaying on mainnet and back. mainnet is unchanged
    @dst_tx_testnet "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_TX_TESTNET_"
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
    def dst_tx(), do: if(Application.get_env(:ama, :testnet), do: @dst_tx_testnet, else: @dst_tx)
    def dst_motion(), do: @dst_motion
    def dst_node(), do: @dst_node
    def dst_anr(), do: @dst_anr
    def dst_anr_challenge(), do: @dst_anr_challenge
    def dst_bundle(), do: @dst_bundle

    def new_padded(%{validators: validators, mask_active: mask_active}) do
        %{mask: Util.pad_bitstring_to_bytes(<<0::size(length(validators))>>), mask_active: mask_active}
    end

    def add_padded(m = %{mask: mask}, set, pk, signature) do
        validate!(m, set)
        index = Util.index_of(ValidatorSet.roster(set), pk)
        cond do
            index == nil -> throw(%{error: :signer_not_in_validator_set})
            !Util.get_bit(set.mask_active, index) -> throw(%{error: :inactive_signer})
            Util.get_bit(mask, index) -> m
            true ->
                signature = if m[:aggsig], do: BlsEx.aggregate_signatures!([m.aggsig, signature]), else: signature
                Map.merge(m, %{mask: Util.set_bit(mask, index), aggsig: signature})
        end
    end

    # The supplied active mask never defines eligibility: it must exactly match
    # the state for the height being verified.
    def validate(m, set) do
        roster = ValidatorSet.roster(set)
        with :ok <- validate_mask(m[:mask], length(roster)),
             true <- Map.get(m, :mask_active) == set.mask_active || {:error, :mask_active_mismatch},
             true <- subset?(m.mask, set.mask_active) || {:error, :inactive_signer} do
            {:ok, unmask_trainers(roster, m.mask, length(roster))}
        end
    end

    def validate!(m, set) do
        case validate(m, set) do
            {:ok, signers} -> signers
            {:error, error} -> throw(%{error: error})
        end
    end

    defp subset?(signed, active) do
        Enum.zip(:binary.bin_to_list(signed), :binary.bin_to_list(active))
        |> Enum.all?(fn {s, a} -> Bitwise.band(s, a) == s end)
    end

    # Only use the one-argument forms for locally built or validated aggregates.
    def active_count(%{mask_active: mask}), do: Util.popcnt(mask)
    def signer_count(%{mask: mask}), do: Util.popcnt(mask)
    def score(m) do
        total = active_count(m)
        if total == 0, do: 0.0, else: signer_count(m) / total
    end
    def quorum?(m), do: quorum?(signer_count(m), active_count(m))

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

    def quorum?(m, set) when is_map(m) do
        case validate(m, set) do
            {:ok, signers} -> quorum?(length(signers), ValidatorSet.active_count(set))
            _ -> false
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
      aggsig = BLS12AggSig.new_padded(total_signer_list)
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
