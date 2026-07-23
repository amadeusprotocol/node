defmodule NodeStatsGen do
    use GenServer

    @supply_interval_ms 6 * 60 * 60 * 1000
    @supply_retry_ms 60_000
    @validators_interval_ms 1_000

    def start_link() do
        GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
    end

    #latest supply snapshot, served as-is between 6h recomputes; nil until the
    #first scan after boot completes. computed_at_height says how stale it is.
    def supply() do
        :persistent_term.get({NodeStatsGen, :supply}, nil)
    end

    #validator map keyed by Base58 pk; sol counts refresh every tick, the
    #vault/commission data only repulls when the validator set actually changes
    #(and on every supply scan). ETS because persistent_term updates force a
    #global GC scan — fine at 6h for supply, not at the fast validator tick.
    def validators() do
        case :ets.lookup(NodeStatsGen, :validators) do
            [{:validators, %{map: map}}] -> map
            _ -> nil
        end
    end

    def init(state) do
        :ets.new(NodeStatsGen, [:named_table, :public, read_concurrency: true])
        :erlang.send_after(3_000, self(), :tick_supply)
        :erlang.send_after(3_000, self(), :tick_validators)
        {:ok, state}
    end

    def handle_info(:tick_supply, state) do
        next_ms = try do
            compute_supply()
            @supply_interval_ms
        catch
            e,r ->
                IO.inspect {NodeStatsGen, :supply_failed, e, r}
                @supply_retry_ms
        end
        :erlang.send_after(next_ms, self(), :tick_supply)
        {:noreply, state}
    end

    def handle_info(:tick_validators, state) do
        try do
            height = DB.Chain.height()
            epoch = div(height, 100_000)
            #height+1: a slash or epoch rollover writes the new set there, so this
            #is the freshest list available
            list = DB.Chain.validators_for_height(height + 1)
            cached = case :ets.lookup(NodeStatsGen, :validators) do
                [{:validators, c}] -> c
                _ -> nil
            end
            if !cached or cached.list != list do
                put_validators(list, scan_vaults(), epoch)
            else
                #set unchanged: stakes/commissions stay as-is, only the cheap live
                #sol counters refresh (they grow every block during an epoch)
                refresh_sols(cached)
            end
        catch
            e,r -> IO.inspect {NodeStatsGen, :validators_failed, e, r}
        end
        :erlang.send_after(@validators_interval_ms, self(), :tick_validators)
        {:noreply, state}
    end

    def compute_supply() do
        opts = contractstate()

        height = DB.Chain.height()
        epoch = div(height, 100_000)

        wallets_flat = sum_wallet_balances(<<"account:", 0::384, ":balance:AMA">>, opts, 0)
        burn_flat = DB.Chain.balance(BIC.Coin.burn_address())

        vaults = scan_vaults()
        vaulted_flat = Enum.sum_by(vaults, & vfield(&1, :amount) + vfield(&1, :accrued))

        circulating_flat = wallets_flat - burn_flat
        total_supply_flat = circulating_flat + vaulted_flat

        :persistent_term.put({NodeStatsGen, :supply}, %{
            total_supply: BIC.Coin.from_flat(total_supply_flat),
            circulating: BIC.Coin.from_flat(circulating_flat),
            total_locked: BIC.Coin.from_flat(vaulted_flat),
            total_supply_flat: total_supply_flat,
            circulating_flat: circulating_flat,
            total_locked_flat: vaulted_flat,
            computed_at_height: height,
        })

        #the vaults are already in hand: refresh validator stakes/commissions too,
        #so they never go more than one supply interval stale even with a static set
        put_validators(DB.Chain.validators_for_height(height + 1), vaults, epoch)
    end

    defp contractstate() do
        %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
        %{db: db, cf: cf.contractstate}
    end

    defp scan_vaults() do
        RocksDB.get_prefix("bic:lockup_vault:vault:", contractstate())
        |> Enum.map(fn({_suffix, bytes})-> RDB.vecpak_decode(bytes) end)
    end

    #walks only account:<pk48>:balance:AMA keys, hopping past other symbols and
    #attributes; the strictly-advancing reseek cannot loop on unexpected keys
    defp sum_wallet_balances(key, opts, acc) do
        case RocksDB.seek_next(key, opts) do
            {<<"account:", pk::384, ":balance:AMA">>, value} ->
                acc = acc + :erlang.binary_to_integer(value)
                sum_wallet_balances(<<"account:", (pk+1)::384, ":balance:AMA">>, opts, acc)
            {<<"account:", pk::384, _::binary>> = seen, _} ->
                target = <<"account:", pk::384, ":balance:AMA">>
                next = if target > seen do target else <<seen::binary, 0>> end
                sum_wallet_balances(next, opts, acc)
            _ -> acc
        end
    end

    defp put_validators(list, vaults, epoch) do
        opts = contractstate()
        sols = sols_by_pk()
        stakes = Enum.reduce(vaults, %{}, fn(vault, acc)->
            case vault_validator(vault, epoch) do
                nil -> acc
                pk ->
                    stake = vfield(vault, :amount) + vfield(vault, :accrued)
                    Map.update(acc, pk, stake, & &1 + stake)
            end
        end)
        map = Enum.uniq(list ++ Map.keys(stakes))
        |> Map.new(fn(pk)->
            staked_flat = Map.get(stakes, pk, 0)
            entry = %{
                staked: BIC.Coin.from_flat(staked_flat),
                staked_flat: staked_flat,
                #any validator can also be solving, so every entry carries its count
                sols: Map.get(sols, pk, 0),
                in_validator_set: :lists.member(pk, list),
            }
            {Base58.encode(pk), Map.merge(entry, commission(pk, epoch, opts))}
        end)
        :ets.insert(NodeStatsGen, {:validators, %{list: list, map: map}})
    end

    #current-epoch sol counts for everyone, keyed by raw pk
    defp sols_by_pk() do
        RocksDB.get_prefix("bic:epoch:solutions_count:", Map.put(contractstate(), :to_integer, true))
        |> Map.new()
    end

    defp refresh_sols(cached = %{map: map}) do
        sols = sols_by_pk()
        map = Map.new(map, fn({pk_b58, entry})->
            {pk_b58, Map.put(entry, :sols, Map.get(sols, Base58.decode(pk_b58), 0))}
        end)
        :ets.insert(NodeStatsGen, {:validators, %{cached | map: map}})
    end

    #a queued validator change (set or clear) applies once its pending epoch is reached
    defp vault_validator(vault, epoch) do
        pending_epoch = vfield(vault, :validator_pending_epoch)
        if pending_epoch != nil and epoch >= pending_epoch do
            vfield(vault, :validator_pending)
        else
            vfield(vault, :validator)
        end
    end

    #a set_commission queues {pending_bps, pending_epoch}; until that epoch the old
    #bps stays effective, so the queued change is reported alongside it
    defp commission(pk, epoch, opts) do
        case RocksDB.get("bic:lockup_vault:validator_commission:#{pk}", opts) do
            nil -> %{commission_bps: 0}
            bytes ->
                c = RDB.vecpak_decode(bytes)
                if epoch >= vfield(c, :pending_epoch) do
                    %{commission_bps: vfield(c, :pending_bps)}
                else
                    %{
                        commission_bps: vfield(c, :bps),
                        commission_pending: %{bps: vfield(c, :pending_bps), epoch: vfield(c, :pending_epoch)},
                    }
                end
        end
    end

    #vecpak proplist keys decode as atoms only when already in the atom table
    defp vfield(map, key) do
        case Map.fetch(map, key) do
            {:ok, v} -> v
            :error -> map[Atom.to_string(key)]
        end
    end
end
