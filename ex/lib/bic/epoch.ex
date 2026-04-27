defmodule BIC.Epoch do
    @epoch_emission_base BIC.Coin.to_flat(1_000_000)
    @epoch_emission_fixed BIC.Coin.to_flat(100_000)
    @epoch_interval 100_000

    @a 23_072_960_000
    @c 1110.573766
    @start_epoch 420

    def epoch_emission(epoch) when epoch >= @start_epoch do
      floor(0.5 * @a / :math.pow(epoch - @start_epoch + @c, 1.5))
      |> BIC.Coin.to_flat()
    end

    def epoch_emission(epoch) when epoch >= 282 do
        epoch_emission_1(epoch)
    end

    def epoch_emission(epoch) when epoch >= 103 do
        epoch_emission_1(epoch) + @epoch_emission_fixed * 2
    end

    def epoch_emission(epoch) do
        epoch_emission_1(epoch) + @epoch_emission_fixed
    end

    defp epoch_emission_1(_epoch, acc \\ @epoch_emission_base)
    defp epoch_emission_1(0, acc) do acc end
    defp epoch_emission_1(epoch, acc) do
        sub = div(acc * 333, 1000000)
        emitted = acc - sub
        epoch_emission_1(epoch - 1, emitted)
    end

    def circulating_without_burn(_epoch, _acc \\ 0)
    def circulating_without_burn(0, acc) do acc end
    def circulating_without_burn(epoch, acc) do
        circulating_without_burn(epoch - 1, acc + epoch_emission(epoch))
    end

    def circulating(epoch) do circulating_without_burn(epoch) - BIC.Coin.burn_balance() end

    @peddlebike67 [
      "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"
    ] |> Enum.map(& Base58.decode(&1))
    def peddlebike67() do @peddlebike67 end

    def slash_trainer_verify(malicious_pk, cur_epoch, trainers, mask, signature) do
        signers = BLS12AggSig.unmask_trainers(trainers, Util.pad_bitstring_to_bytes(mask), bit_size(mask))

        consensus_pct = length(signers) / length(trainers)

        apk = BlsEx.aggregate_public_keys!(signers)
        msg = <<"slash_trainer", cur_epoch::32-little, malicious_pk::binary>>
        validSignature = BlsEx.verify?(apk, signature, msg, BLS12AggSig.dst_motion())
        cond do
            consensus_pct < 0.67 -> :invalid_amount_of_signatures
            !validSignature -> :invalid_signature
            true -> nil
        end
    end
end
