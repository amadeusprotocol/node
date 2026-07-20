defmodule API.Vault do
    @vault_min_flat 1000 * 1_000_000_000

    defp to_flat(amount) do
        cond do
            is_float(amount) -> trunc(amount * 1_000_000_000)
            is_integer(amount) -> amount
            true -> throw(%{error: :invalid_amount})
        end
    end

    defp pk!(pk, err) do
        pk = API.maybe_b58(48, pk)
        if byte_size(pk) != 48 or !BlsEx.validate_public_key(pk), do: throw(%{error: err, pk: Base58.encode(pk)})
        pk
    end

    defp index_bin(vault_index) do
        cond do
            is_integer(vault_index) -> :erlang.integer_to_binary(vault_index)
            is_binary(vault_index) -> vault_index
            true -> throw(%{error: :invalid_vault_index})
        end
    end

    # opts: :validator, :payout_address, :owner (Base58 or raw pk),
    #       :unlock_epoch (int), :months (int, og tier only)
    def create(from_sk, amount, tier \\ "og", opts \\ [], broadcast \\ true) do
        from_sk = API.maybe_b58(64, from_sk)
        amount = to_flat(amount)
        if amount < @vault_min_flat, do: throw(%{error: :vault_amount_below_minimum, min_flat: @vault_min_flat})
        if !is_binary(tier), do: throw(%{error: :invalid_tier})

        map =
            %{"amount" => amount, "tier" => tier}
            |> maybe_put_pk("validator", opts[:validator], :invalid_validator_pk)
            |> maybe_put_pk("payout_address", opts[:payout_address], :invalid_payout_pk)
            |> maybe_put_pk("owner", opts[:owner], :invalid_owner_pk)
            |> maybe_put_int("unlock_epoch", opts[:unlock_epoch])
            |> maybe_put_int("months", opts[:months])

        blob = RDB.vecpak_encode(map)
        build(from_sk, "create", [blob], broadcast)
    end

    defp maybe_put_pk(map, _key, nil, _err), do: map
    defp maybe_put_pk(map, key, pk, err), do: Map.put(map, key, pk!(pk, err))

    defp maybe_put_int(map, _key, nil), do: map
    defp maybe_put_int(map, key, v) when is_integer(v), do: Map.put(map, key, v)

    def unlock(from_sk, vault_index, broadcast \\ true) do
        build(API.maybe_b58(64, from_sk), "unlock", [index_bin(vault_index)], broadcast)
    end

    def set_payout_address(from_sk, vault_index, payout_pk, broadcast \\ true) do
        build(API.maybe_b58(64, from_sk), "set_payout_address",
            [index_bin(vault_index), pk!(payout_pk, :invalid_payout_pk)], broadcast)
    end

    def clear_payout_address(from_sk, vault_index, broadcast \\ true) do
        build(API.maybe_b58(64, from_sk), "clear_payout_address", [index_bin(vault_index)], broadcast)
    end

    def set_validator(from_sk, vault_index, validator_pk, broadcast \\ true) do
        build(API.maybe_b58(64, from_sk), "set_validator",
            [index_bin(vault_index), pk!(validator_pk, :invalid_validator_pk)], broadcast)
    end

    def clear_validator(from_sk, vault_index, broadcast \\ true) do
        build(API.maybe_b58(64, from_sk), "clear_validator", [index_bin(vault_index)], broadcast)
    end

    def change_owner(from_sk, vault_index, new_owner_pk, broadcast \\ true) do
        build(API.maybe_b58(64, from_sk), "change_owner",
            [index_bin(vault_index), pk!(new_owner_pk, :invalid_owner_pk)], broadcast)
    end

    def extend_lock(from_sk, vault_index, months, broadcast \\ true) when is_integer(months) do
        build(API.maybe_b58(64, from_sk), "extend_lock",
            [index_bin(vault_index), :erlang.integer_to_binary(months)], broadcast)
    end

    # commission in bps (0..=10000) on validator yield; applies to the caller's pk
    def set_commission(from_sk, bps, broadcast \\ true) when is_integer(bps) do
        build(API.maybe_b58(64, from_sk), "set_commission",
            [:erlang.integer_to_binary(bps)], broadcast)
    end

    defp build(from_sk, function, args, broadcast) do
        txu = TX.build(from_sk, "LockupVault", function, args)
        broadcast && TXPool.insert_and_broadcast(txu)
        txu
    end

    # convenience read: all vaults owned by a pubkey, decoded
    def by_owner(owner) do
        owner = API.maybe_b58(48, owner)
        %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
        opts = %{db: db, cf: cf.contractstate}
        RocksDB.get_prefix("bic:lockup_vault:vault:#{owner}:", opts)
        |> Enum.map(fn {index, bytes} ->
            %{index: index, vault: RDB.vecpak_decode(bytes)}
        end)
    end
end
