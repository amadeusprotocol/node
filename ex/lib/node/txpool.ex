defmodule TXPool do
    #TXPool row:        {{nonce, hash}, txu, tx_bytes, reserved_ama}   (tx_bytes = packed size)
    #TXPoolAccount row: {signer, count, reserved_ama}
    #the pool is capped at txpool_max_bytes, and a signer's pending txs can never
    #reserve more AMA than its chain balance (exec + storage reserve + historical cost per tx)

    def init_byte_counter() do
        :persistent_term.put({__MODULE__, :bytes}, :atomics.new(1, []))
    end

    #decoded map + ETS row cost ~1KB over the packed size (3-4x for small txs)
    @row_overhead 1024
    def row_overhead(), do: @row_overhead

    #counts packed bytes + @row_overhead per tx, so it tracks real memory
    def bytes(), do: :atomics.get(byte_counter(), 1)
    def max_bytes(), do: Application.fetch_env!(:ama, :txpool_max_bytes)

    def tx_reserve_ama() do
        RDBProtocol.reserve_ama_per_tx_exec() * 2 + RDBProtocol.reserve_ama_per_tx_storage()
    end

    def reserve_ama(txu) do
        tx_reserve_ama() + TX.historical_cost(nil, txu)
    end

    def signer_reservation(signer) do
        case :ets.lookup(TXPoolAccount, signer) do
            [{_, count, reserved_ama}] -> %{count: count, reserved_ama: reserved_ama}
            [] -> %{count: 0, reserved_ama: 0}
        end
    end

    #args (all optional) are validate_tx args plus :chain_balance
    #each tx is admitted on its own against chain state; gossip order must not matter,
    #and the per-signer reservation already bounds what a signer can queue
    def insert(txu, args \\ %{})
    def insert(txus, args) when is_list(txus) do
        args = chain_args(args)
        Enum.each(txus, & admit(&1, args))
        :ok
    end
    def insert(txu, args) when is_map(txu) do
        admit(txu, chain_args(args))
    end

    #DB.Chain.height/epoch each decode the whole tip entry: resolve once per insert call
    defp chain_args(args) do
        height = Map.get_lazy(args, :height, fn()-> DB.Chain.height() end)
        Map.merge(%{height: height, epoch: div(height, 100_000)}, args)
    end

    #an already-pooled tx is re-broadcast too (a lost first broadcast would
    #strand it, receivers never relay), but at most once per @rebroadcast_ms
    #since the duplicate path skips the BLS check
    @rebroadcast_ms 5_000
    def insert_and_broadcast(txu, opts \\ %{}) do
        case insert(txu) do
            %{error: :ok, txu: txu} = result ->
                if broadcast_due?({txu.tx.nonce, txu.hash}) do
                    NodeGen.broadcast(NodeProto.event_tx(txu), opts)
                end
                result
            result -> result
        end
    end

    defp broadcast_due?(key) do
        now = :os.system_time(1000)
        case :ets.lookup(TXPoolBroadcast, key) do
            [{_, last}] when now - last < @rebroadcast_ms -> false
            _ -> :ets.insert(TXPoolBroadcast, {key, now})
        end
    end

    def delete_packed(txu) when is_map(txu) do delete_packed([txu]) end
    def delete_packed(txus) do
        Enum.each(txus, & delete_key({&1.tx.nonce, &1.hash}))
    end

    #cheapest checks first, BLS verify last, reserve only once everything passed
    defp admit(txu, args) do
        with %{error: :ok, txu: txu} <- TX.validate_structure(txu),
             key = {txu.tx.nonce, txu.hash},
             false <- :ets.member(TXPool, key),
             signer = txu.tx.signer,
             balance = Map.get_lazy(args, :chain_balance, fn()-> DB.Chain.balance(signer) end),
             batch_state = Map.put_new(Map.get(args, :batch_state, %{}), {:balance, signer}, balance),
             %{error: :ok} <- validate_tx(txu, Map.put(args, :batch_state, batch_state)),
             tx_bytes = byte_size(TX.pack(txu)),
             reserved_ama = reserve_ama(txu),
             :ok <- check_capacity(txu, tx_bytes, reserved_ama, balance),
             %{error: :ok} <- TX.validate_signature(txu) do
            reserve_and_insert(key, txu, tx_bytes, reserved_ama, balance)
        else
            true -> %{error: :ok, txu: txu, inserted: false}
            error -> error
        end
    end

    defp check_capacity(txu, tx_bytes, reserved_ama, balance) do
        cond do
            bytes() + tx_bytes + @row_overhead > max_bytes() -> pool_full_error()
            signer_reservation(txu.tx.signer).reserved_ama + reserved_ama > balance -> signer_full_error(txu, reserved_ama, balance)
            true -> :ok
        end
    end

    #check_capacity is only a fast path, concurrent admits race past it; these reservations are the hard limits
    defp reserve_and_insert(key, txu, tx_bytes, reserved_ama, balance) do
        signer = txu.tx.signer
        [_count, signer_reserved] = :ets.update_counter(TXPoolAccount, signer, [{2, 1}, {3, reserved_ama}], {signer, 0, 0})
        cond do
            signer_reserved > balance ->
                release_signer(signer, reserved_ama)
                signer_full_error(txu, reserved_ama, balance)
            !reserve_bytes(tx_bytes) ->
                release_signer(signer, reserved_ama)
                pool_full_error()
            :ets.insert_new(TXPool, {key, txu, tx_bytes, reserved_ama}) ->
                %{error: :ok, txu: txu, inserted: true}
            true ->
                #lost a race against the same tx
                release_bytes(tx_bytes)
                release_signer(signer, reserved_ama)
                %{error: :ok, txu: txu, inserted: false}
        end
    end

    #take + release is not atomic: callers must never be killed mid-delete (see NodeGen :tick_purge_txpool)
    defp delete_key(key) do
        case :ets.take(TXPool, key) do
            [{_, txu, tx_bytes, reserved_ama}] ->
                :ets.delete(TXPoolBroadcast, key)
                release_bytes(tx_bytes)
                release_signer(txu.tx.signer, reserved_ama)
                true
            [] -> false
        end
    end

    defp reserve_bytes(tx_bytes) do
        amount = tx_bytes + @row_overhead
        counter = byte_counter()
        current = :atomics.get(counter, 1)
        cond do
            current + amount > max_bytes() -> false
            :atomics.compare_exchange(counter, 1, current, current + amount) == :ok -> true
            true -> reserve_bytes(tx_bytes)
        end
    end

    defp release_bytes(tx_bytes), do: :atomics.sub(byte_counter(), 1, tx_bytes + @row_overhead)

    defp release_signer(signer, reserved_ama) do
        case :ets.update_counter(TXPoolAccount, signer, [{2, -1}, {3, -reserved_ama}]) do
            #only removes the row if nobody reserved again in between
            [0, 0] -> :ets.delete_object(TXPoolAccount, {signer, 0, 0})
            _ -> true
        end
    end

    defp byte_counter(), do: :persistent_term.get({__MODULE__, :bytes})

    defp pool_full_error(), do: %{error: :txpool_full, current_bytes: bytes(), max_bytes: max_bytes()}

    defp signer_full_error(txu, reserved_ama, balance) do
        reserved = signer_reservation(txu.tx.signer).reserved_ama
        %{error: :not_enough_txpool_balance, key: {txu.tx.nonce, txu.hash},
          balance: balance, reserved_ama: reserved, required_ama: reserved + reserved_ama}
    end

    #pass 1 drops stale txs so they stop counting against their signer; pass 2 walks
    #newest first and drops a signer's highest nonces while its live reservation
    #exceeds its live balance (live, so txs admitted mid-run are judged correctly)
    def purge_stale() do
        cur_epoch = DB.Chain.epoch()
        segment_vr_hash = DB.Chain.segment_vr_hash()
        :ets.foldl(fn({key, txu, _, _}, :ok)->
            if is_stale(txu, cur_epoch, segment_vr_hash), do: delete_key(key)
            :ok
        end, :ok, TXPool)
        :ets.foldr(fn({key, txu, _, _}, :ok)->
            signer = txu.tx.signer
            if signer_reservation(signer).reserved_ama > DB.Chain.balance(signer), do: delete_key(key)
            :ok
        end, :ok, TXPool)
        :ok
    end

    def is_stale(txu, cur_epoch, segment_vr_hash \\ DB.Chain.segment_vr_hash()) do
        chainNonce = DB.Chain.nonce(txu.tx.signer)
        nonceValid = !chainNonce or txu.tx.nonce > chainNonce

        action = TX.action(txu)
        solGateOk =
          if action.function == "submit_sol" do
            case action.args do
              [<<sol_epoch::32-little, sol_segment::32-binary, _::binary>> = sol | _] ->
                cur_epoch == sol_epoch and sol_segment == segment_vr_hash and byte_size(sol) == BIC.Sol.size()
              _ -> false
            end
          else
            true
          end

        cond do
            !solGateOk -> true
            !nonceValid -> true
            true -> false
        end
    end

    def validate_tx(txu, args \\ %{}) do
      chain_epoch = Map.get_lazy(args, :epoch, fn()-> DB.Chain.epoch() end)
      chain_height = Map.get_lazy(args, :height, fn()-> DB.Chain.height() end)
      batch_state = Map.get_lazy(args, :batch_state, fn()-> %{} end)

      try do
        chainNonce = Map.get_lazy(batch_state, {:chain_nonce, txu.tx.signer}, fn()-> DB.Chain.nonce(txu.tx.signer) end)
        nonceValid = !chainNonce or txu.tx.nonce > chainNonce
        if !nonceValid, do: throw(%{error: :invalid_tx_nonce, key: {txu.tx.nonce, txu.hash}})
        batch_state = Map.put(batch_state, {:chain_nonce, txu.tx.signer}, txu.tx.nonce)

        balance = Map.get_lazy(batch_state, {:balance, txu.tx.signer}, fn()-> DB.Chain.balance(txu.tx.signer) end)
        balance = balance - (RDBProtocol.reserve_ama_per_tx_exec() * 2)
        balance = balance - RDBProtocol.reserve_ama_per_tx_storage()
        balance = balance - TX.historical_cost(chain_height, txu)
        if balance < 0, do: throw(%{error: :not_enough_tx_exec_balance, key: {txu.tx.nonce, txu.hash}})
        batch_state = Map.put(batch_state, {:balance, txu.tx.signer}, balance)

        action = TX.action(txu)
        if action.function == "submit_sol" do
          #only sols need these, so other txs skip the reads
          chain_segment_vr_hash = Map.get_lazy(args, :segment_vr_hash, fn()-> DB.Chain.segment_vr_hash() end)
          chain_diff_bits = Map.get_lazy(args, :diff_bits, fn()-> DB.Chain.diff_bits() end)
          with [<<sol_epoch::32-little, sol_svrh::32-binary, _::binary>> = arg0 | _] <- action.args,
               true <- sol_epoch == chain_epoch,
               true <- sol_svrh == chain_segment_vr_hash,
               true <- byte_size(arg0) == BIC.Sol.size(),
               true <- BIC.Sol.verify_hash_diff(chain_epoch, Blake3.hash(arg0), chain_diff_bits) do
            :ok
          else
            _ -> throw(%{error: :invalid_tx_sol, key: {txu.tx.nonce, txu.hash}})
          end
        end

        %{error: :ok, batch_state: batch_state}
      catch
        :throw, r -> r
      end
    end

    def grab_next_valid(chain_height, max_bytes \\ Entry.entry_max_txs_bytes()) do
        try do
            chain_epoch = div(chain_height, 100_000)

            segment_vr_hash = DB.Chain.segment_vr_hash()
            {acc, _state, _bytes} = :ets.foldl(fn({key, txu, tx_size, _reserved_ama}, {acc, state_old, total_bytes})->
                if total_bytes + tx_size > max_bytes do
                    if length(acc) > 0 do
                        throw {:choose, Enum.reverse(acc)}
                    else
                        {acc, state_old, total_bytes}
                    end
                else
                  case validate_tx(txu, %{epoch: chain_epoch, height: chain_height, segment_vr_hash: segment_vr_hash, batch_state: state_old}) do
                    %{error: :ok, batch_state: batch_state} ->
                      acc = [txu | acc]
                      if total_bytes + tx_size >= max_bytes do
                          throw {:choose, Enum.reverse(acc)}
                      end
                      {acc, batch_state, total_bytes + tx_size}
                    _ ->
                      delete_key(key)
                      {acc, state_old, total_bytes}
                  end
                end
            end, {[], %{}, 0}, TXPool)
            Enum.reverse(acc)
        catch
            :throw,{:choose, txs_packed} -> txs_packed
        end
    end

    def random(amount \\ 2)
    def random(0), do: []
    def random(amount) do
        case :ets.select(TXPool, [{{:"$1", :"$2", :_, :_}, [], [{{:"$1", :"$2"}}]}], amount) do
            {[_|_] = txus, _cont} -> txus
            _ -> nil
        end
    end

    def lowest_nonce(pk) do
        :ets.foldl(fn({{nonce, _hash}, txu, _, _}, lowest_nonce)->
            if txu.tx.signer == pk and (lowest_nonce == nil or nonce < lowest_nonce), do: nonce, else: lowest_nonce
        end, nil, TXPool)
    end

    def highest_nonce() do
        Application.fetch_env!(:ama, :trainer_pk)
        |> highest_nonce()
    end
    def highest_nonce(pk) do
        :ets.foldl(fn({{nonce, _hash}, txu, _, _}, {highest_nonce, cnt})->
            cond do
                txu.tx.signer == pk and (highest_nonce == nil or nonce > highest_nonce) -> {nonce, cnt + 1}
                txu.tx.signer == pk -> {highest_nonce, cnt + 1}
                true -> {highest_nonce, cnt}
            end
        end, {nil, 0}, TXPool)
    end

    def size() do
      :ets.info(TXPool, :size)
    end
end
