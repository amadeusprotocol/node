defmodule TXPool do
    def insert(tx) when is_map(tx) do insert([tx]) end
    def insert([]) do :ok end
    def insert(txus) do
        txus = Enum.map(txus, fn(txu)->
            {{txu.tx.nonce, txu.hash}, txu}
        end)
        :ets.insert(TXPool, txus)
    end

    def delete_packed(txu) when is_map(txu) do delete_packed([txu]) end
    def delete_packed([]) do :ok end
    def delete_packed(txus) do
        Enum.each(txus, fn(txu)->
            :ets.delete(TXPool, {txu.tx.nonce, txu.hash})
        end)
    end

    def insert_and_broadcast(txu, opts \\ %{}) do
      TXPool.insert(txu)
      NodeGen.broadcast(NodeProto.event_tx(txu), opts)
    end

    def purge_stale() do
        cur_epoch = DB.Chain.epoch()
        :ets.tab2list(TXPool)
        |> Enum.each(fn {key, txu} ->
            if is_stale(txu, cur_epoch) do
                :ets.delete(TXPool, key)
            end
        end)
    end

    def is_stale(txu, cur_epoch) do
        chainNonce = DB.Chain.nonce(txu.tx.signer)
        nonceValid = !chainNonce or txu.tx.nonce > chainNonce

        action = TX.action(txu)
        solGateOk =
          if action.function == "submit_sol" do
            case action.args do
              [<<sol_epoch::32-little, _::binary>> | _] -> cur_epoch == sol_epoch
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
      chain_segment_vr_hash = Map.get_lazy(args, :segment_vr_hash, fn()-> DB.Chain.segment_vr_hash() end)
      chain_diff_bits = Map.get_lazy(args, :diff_bits, fn()-> DB.Chain.diff_bits() end)
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
          with [<<sol_epoch::32-little, sol_svrh::32-binary, _::binary>> = arg0 | _] <- action.args,
               true <- sol_epoch == chain_epoch,
               true <- sol_svrh == chain_segment_vr_hash,
               true <- byte_size(arg0) == BIC.Sol.size() do
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

    #TODO: fix this, we dont need to validate VS chain here
    def event_tx_validate(txu) when is_map(txu) do event_tx_validate([txu]) end
    def event_tx_validate(txus) when is_list(txus) do
      chain_epoch = DB.Chain.epoch()
      chain_height = DB.Chain.height()
      segment_vr_hash = DB.Chain.segment_vr_hash()
      diff_bits = DB.Chain.diff_bits()

      {good, _} = Enum.reduce(txus, {[], %{}}, fn(txu, {acc, batch_state})->
        case TX.validate(txu) do
          %{error: :ok, txu: txu} ->
            case TXPool.validate_tx(txu, %{epoch: chain_epoch, height: chain_height, segment_vr_hash: segment_vr_hash, diff_bits: diff_bits, batch_state: batch_state}) do
              %{error: :ok, batch_state: batch_state} -> {acc ++ [txu], batch_state}
              %{error: error} -> {acc, batch_state}
            end
          _ -> {acc, batch_state}
        end
      end)

      good
    end

    def grab_next_valid(chain_height, amt \\ 1) do
        try do
            chain_epoch = div(chain_height, 100_000)

            segment_vr_hash = DB.Chain.segment_vr_hash()
            {acc, state} = :ets.foldl(fn({key, txu}, {acc, state_old})->
                try do
                  #TODO: remove this redundant validate
                  case TX.validate(txu) do
                    %{error: :ok, txu: txu} ->
                      case validate_tx(txu, %{epoch: chain_epoch, height: chain_height, segment_vr_hash: segment_vr_hash, batch_state: state_old}) do
                        %{error: :ok, batch_state: batch_state} ->
                          acc = acc ++ [txu]
                          if length(acc) == amt do
                              throw {:choose, acc}
                          end
                          {acc, batch_state}
                        #delete stale
                        %{key: key} ->
                          :ets.delete(TXPool, key)
                          {acc, state_old}
                      end
                    _ ->
                      :ets.delete(TXPool, key)
                      {acc, state_old}
                  end
                catch
                    :throw,{:choose, txs_packed} -> throw {:choose, txs_packed}
                end
            end, {[], %{}}, TXPool)
            acc
        catch
            :throw,{:choose, txs_packed} -> txs_packed
        end
    end

    def random(amount \\ 2) do
        :ets.tab2list(TXPool)
        |> case do
            [] -> nil
            txus -> Enum.take(txus, amount)
        end
    end

    def lowest_nonce(pk) do
        :ets.tab2list(TXPool)
        |> Enum.reduce(nil, fn({{nonce, _hash}, txu}, lowest_nonce) ->
            if txu.tx.signer == pk do
                cond do
                    lowest_nonce == nil -> nonce
                    nonce < lowest_nonce -> nonce
                    true -> lowest_nonce
                end
            else
                lowest_nonce
            end
        end)
    end

    def highest_nonce() do
        Application.fetch_env!(:ama, :trainer_pk)
        |> highest_nonce()
    end
    def highest_nonce(pk) do
        :ets.tab2list(TXPool)
        |> Enum.reduce({nil, 0}, fn({{nonce, _hash}, txu}, {highest_nonce, cnt})->
            cond do
                txu.tx.signer == pk and (highest_nonce == nil or nonce > highest_nonce) -> {nonce, cnt + 1}
                txu.tx.signer == pk -> {highest_nonce, cnt + 1}
                true -> {highest_nonce, cnt}
            end
        end)
    end

    def size() do
      :ets.info(TXPool, :size)
    end
end
