defmodule Attestation do
    #a claim (see Claim) plus signer and signature over Claim.pack

    def pack_for_db(attestation_unpacked) when is_binary(attestation_unpacked) do attestation_unpacked end
    def pack_for_db(attestation_unpacked) do
      attestation_unpacked
      |> unpack()
      |> RDB.vecpak_encode()
    end

    def unpack(a), do: Map.merge(Claim.take(a), Map.take(a, [:signer, :signature]))

    def sign(sk, claim) do
        Map.merge(claim, %{
            signer: BlsEx.get_public_key!(sk),
            signature: BlsEx.sign!(sk, Claim.pack(claim), BLS12AggSig.dst_att()),
        })
    end

    def validate(a) do
      try do
        a = unpack(a)

        if !Claim.valid?(a), do: throw(%{error: :invalid_claim})
        if !is_binary(a.signer), do: throw(%{error: :signer_not_binary})
        if byte_size(a.signer) != 48, do: throw(%{error: :signer_not_48_bytes})

        if !BlsEx.verify?(a.signer, a.signature, Claim.pack(a), BLS12AggSig.dst_att()), do: throw(%{error: :invalid_signature})

        %{error: :ok, attestation: a}
      catch
          :throw,r -> r
          e,r -> IO.inspect {Attestation, :validate, e, r}; %{error: :unknown}
      end
    end
end
