defmodule Consensus do
    #a claim (see Claim) plus aggsig %{aggsig, mask, mask_active} over Claim.pack

    def validate_vs_chain(c, verified_roster_hash \\ nil) do
        try do
        entry = DB.Entry.by_hash(c.entry_hash)
        if !entry, do: throw(%{error: :invalid_entry})
        if entry.header.height > DB.Chain.height(), do: throw(%{error: :too_far_in_future})
        if !Claim.for_height?(c, Entry.height(entry)), do: throw(%{error: :invalid_claim})

        set = DB.Chain.validator_set_for_height(Entry.height(entry))
        validators_signed = BLS12AggSig.validate!(c.aggsig, set)
        if verified_roster_hash != roster_hash(set) and !signature_valid?(c, validators_signed), do: throw(%{error: :invalid_signature})

        %{error: :ok}
        catch
            :throw,r -> r
            e,r -> IO.inspect({Consensus, :validate, e, r, __STACKTRACE__}, limit: 111111); %{error: :unknown}
        end
    end

    def roster_hash(set), do: Blake3.hash(Enum.join(ValidatorSet.roster(set)))

    def signature_valid?(c, signers) do
        aggpk = BlsEx.aggregate_public_keys!(signers)
        BlsEx.verify?(aggpk, c.aggsig.aggsig, Claim.pack(c), BLS12AggSig.dst_att())
    end

    def verify_signature_vs_epoch_roster(c, height) do
        epoch_roster_known = div(height, 100_000) <= div(DB.Chain.height() + 1, 100_000)
        if epoch_roster_known do
            set = DB.Chain.validator_set_for_height(height)
            roster = ValidatorSet.roster(set)
            valid = BLS12AggSig.validate_mask(c.aggsig.mask, length(roster)) == :ok
              and signature_valid?(c, BLS12AggSig.unmask_trainers(roster, c.aggsig.mask, length(roster)))
            if valid, do: roster_hash(set), else: :invalid
        end
    end
end
