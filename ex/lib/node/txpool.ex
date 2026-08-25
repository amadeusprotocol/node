defmodule TXPool do
  @purge_batch_size 100_000
  @purge_match_spec [{{:"$1", :"$2", :"$3", :"$4"}, [], [:"$_"]}]

  def init_byte_counter() do
    counter = :atomics.new(1, [])
    :persistent_term.put({__MODULE__, :byte_counter}, counter)
    :ok
  end

  def bytes() do
    :atomics.get(byte_counter(), 1)
  end

  def max_bytes() do
    Application.fetch_env!(:ama, :txpool_max_bytes)
  end

  def tx_reserve_ama() do
    RDBProtocol.reserve_ama_per_tx_exec() * 2 + RDBProtocol.reserve_ama_per_tx_storage()
  end

  def signer_reservation(signer) when is_binary(signer) do
    case :ets.lookup(TXPoolAccount, signer) do
      [{^signer, count, reserved_ama}] -> %{count: count, reserved_ama: reserved_ama}
      [] -> %{count: 0, reserved_ama: 0}
    end
  end

  def insert(tx) when is_map(tx) do
    insert(tx, %{})
  end

  def insert([]) do
    :ok
  end

  def insert(txus) when is_list(txus) do
    Enum.reduce(txus, %{}, fn txu, batch_state ->
      {_result, batch_state} = validate_and_insert(txu, batch_state, %{})
      batch_state
    end)

    :ok
  end

  @doc false
  def insert(tx, validation_args) when is_map(tx) and is_map(validation_args) do
    batch_state = Map.get(validation_args, :batch_state, %{})
    validation_args = Map.delete(validation_args, :batch_state)
    {result, _batch_state} = validate_and_insert(tx, batch_state, validation_args)
    result
  end

  def delete_packed(txu) when is_map(txu) do
    delete_packed([txu])
  end

  def delete_packed([]) do
    :ok
  end

  def delete_packed(txus) do
    Enum.each(txus, fn txu ->
      delete_key({txu.tx.nonce, txu.hash})
    end)
  end

  def insert_and_broadcast(txu, opts \\ %{}) do
    case TXPool.insert(txu) do
      %{error: :ok, txu: txu} = result ->
        if result.inserted, do: NodeGen.broadcast(NodeProto.event_tx(txu), opts)
        result

      error ->
        error
    end
  end

  defp validate_and_insert(txu, batch_state, validation_args) do
    case TX.validate_structure(txu) do
      %{error: :ok, txu: txu} ->
        key = {txu.tx.nonce, txu.hash}

        case :ets.lookup(TXPool, key) do
          [{^key, existing, _tx_bytes, _reserved_ama}] ->
            {%{error: :ok, txu: existing, inserted: false}, batch_state}

          [] ->
            validate_reserve_and_insert(key, txu, batch_state, validation_args)
        end

      error ->
        {error, batch_state}
    end
  end

  defp validate_reserve_and_insert(key, txu, batch_state, validation_args) do
    case validate_tx(txu, Map.put(validation_args, :batch_state, batch_state)) do
      %{error: :ok, batch_state: proposed_batch_state, chain_balance: chain_balance} ->
        tx_bytes = byte_size(TX.pack(txu))
        reserved_ama = tx_reserve_ama()

        cond do
          bytes() + tx_bytes > max_bytes() ->
            {pool_full_error(), batch_state}

          !signer_has_capacity?(txu.tx.signer, reserved_ama, chain_balance) ->
            {signer_full_error(txu, chain_balance, reserved_ama), batch_state}

          true ->
            verify_and_insert(
              key,
              txu,
              tx_bytes,
              reserved_ama,
              chain_balance,
              batch_state,
              proposed_batch_state,
              validation_args
            )
        end

      error ->
        {error, batch_state}
    end
  end

  defp verify_and_insert(
         key,
         txu,
         tx_bytes,
         reserved_ama,
         chain_balance,
         batch_state,
         proposed_batch_state,
         validation_args
       ) do
    case TX.validate_signature(txu) do
      %{error: :ok} = result ->
        case reserve_signer_ama(
               TXPoolAccount,
               txu.tx.signer,
               reserved_ama,
               chain_balance
             ) do
          {:ok, _count, _total_reserved} ->
            reserve_bytes_and_insert(
              key,
              txu,
              tx_bytes,
              reserved_ama,
              batch_state,
              proposed_batch_state,
              validation_args,
              result
            )

          {:error, _count, _total_reserved} ->
            {signer_full_error(txu, chain_balance, reserved_ama), batch_state}
        end

      error ->
        {error, batch_state}
    end
  end

  defp reserve_bytes_and_insert(
         key,
         txu,
         tx_bytes,
         reserved_ama,
         batch_state,
         proposed_batch_state,
         validation_args,
         result
       ) do
    if reserve_pool_bytes(tx_bytes) do
      if :ets.insert_new(TXPool, {key, txu, tx_bytes, reserved_ama}) do
        {Map.put(result, :inserted, true), proposed_batch_state}
      else
        release_pool_bytes(tx_bytes)
        release_signer_ama(TXPoolAccount, txu.tx.signer, reserved_ama)

        case :ets.lookup(TXPool, key) do
          [{^key, existing, _existing_bytes, _existing_reserve}] ->
            {%{error: :ok, txu: existing, inserted: false}, proposed_batch_state}

          [] ->
            validate_and_insert(txu, batch_state, validation_args)
        end
      end
    else
      release_signer_ama(TXPoolAccount, txu.tx.signer, reserved_ama)
      {pool_full_error(), batch_state}
    end
  end

  def purge_batch_size(), do: @purge_batch_size

  def purge_stale() do
    purge_stale(:start, @purge_batch_size)
    :ok
  end

  def purge_stale(continuation), do: purge_stale(continuation, @purge_batch_size)

  def purge_stale(continuation, limit)
      when is_integer(limit) and limit > 0 do
    cur_epoch = DB.Chain.epoch()

    case select_purge_batch(continuation, limit) do
      :"$end_of_table" ->
        {:done, 0}

      {entries, next_continuation} ->
        purge_entries(entries, cur_epoch)
        processed = length(entries)

        if next_continuation == :"$end_of_table" do
          {:done, processed}
        else
          {:continue, next_continuation, processed}
        end
    end
  end

  defp select_purge_batch(:start, limit) do
    :ets.select_reverse(TXPool, @purge_match_spec, limit)
  end

  defp select_purge_batch(continuation, _limit) do
    :ets.select(continuation)
  end

  defp purge_entries(entries, cur_epoch) do
    Enum.reduce(entries, %{}, fn {key, txu, _tx_bytes, _reserved_ama}, balances ->
      signer = txu.tx.signer

      if is_stale(txu, cur_epoch) do
        delete_key(key)
        balances
      else
        balance = Map.get_lazy(balances, signer, fn -> DB.Chain.balance(signer) end)

        if signer_reservation(signer).reserved_ama > balance do
          delete_key(key)
        end

        Map.put(balances, signer, balance)
      end
    end)

    :ok
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
    chain_epoch = Map.get_lazy(args, :epoch, fn -> DB.Chain.epoch() end)
    chain_height = Map.get_lazy(args, :height, fn -> DB.Chain.height() end)

    chain_segment_vr_hash =
      Map.get_lazy(args, :segment_vr_hash, fn -> DB.Chain.segment_vr_hash() end)

    chain_diff_bits = Map.get_lazy(args, :diff_bits, fn -> DB.Chain.diff_bits() end)
    batch_state = Map.get_lazy(args, :batch_state, fn -> %{} end)

    try do
      chainNonce =
        Map.get_lazy(
          batch_state,
          {:chain_nonce, txu.tx.signer},
          fn -> DB.Chain.nonce(txu.tx.signer) end
        )

      nonceValid = !chainNonce or txu.tx.nonce > chainNonce
      if !nonceValid, do: throw(%{error: :invalid_tx_nonce, key: {txu.tx.nonce, txu.hash}})
      batch_state = Map.put(batch_state, {:chain_nonce, txu.tx.signer}, txu.tx.nonce)

      chain_balance =
        case Map.fetch(batch_state, {:chain_balance, txu.tx.signer}) do
          {:ok, balance} ->
            balance

          :error ->
            Map.get_lazy(batch_state, {:balance, txu.tx.signer}, fn ->
              DB.Chain.balance(txu.tx.signer)
            end)
        end

      balance = Map.get(batch_state, {:balance, txu.tx.signer}, chain_balance)

      balance = balance - RDBProtocol.reserve_ama_per_tx_exec() * 2
      balance = balance - RDBProtocol.reserve_ama_per_tx_storage()
      balance = balance - TX.historical_cost(chain_height, txu)

      if balance < 0,
        do: throw(%{error: :not_enough_tx_exec_balance, key: {txu.tx.nonce, txu.hash}})

      batch_state =
        batch_state
        |> Map.put({:chain_balance, txu.tx.signer}, chain_balance)
        |> Map.put({:balance, txu.tx.signer}, balance)

      action = TX.action(txu)

      if action.function == "submit_sol" do
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

      %{error: :ok, batch_state: batch_state, chain_balance: chain_balance}
    catch
      :throw, r -> r
    end
  end

  def grab_next_valid(chain_height, max_bytes \\ Entry.entry_max_txs_bytes()) do
    try do
      chain_epoch = div(chain_height, 100_000)

      segment_vr_hash = DB.Chain.segment_vr_hash()

      {acc, _state, _bytes} =
        :ets.foldl(
          fn {key, txu, tx_size, _reserved_ama}, {acc, state_old, total_bytes} ->
            if total_bytes + tx_size > max_bytes do
              if length(acc) > 0 do
                throw({:choose, Enum.reverse(acc)})
              else
                {acc, state_old, total_bytes}
              end
            else
              case validate_tx(txu, %{
                     epoch: chain_epoch,
                     height: chain_height,
                     segment_vr_hash: segment_vr_hash,
                     batch_state: state_old
                   }) do
                %{error: :ok, batch_state: batch_state} ->
                  acc = [txu | acc]

                  if total_bytes + tx_size >= max_bytes do
                    throw({:choose, Enum.reverse(acc)})
                  end

                  {acc, batch_state, total_bytes + tx_size}

                # delete stale
                %{key: key} ->
                  delete_key(key)
                  {acc, state_old, total_bytes}

                _ ->
                  delete_key(key)
                  {acc, state_old, total_bytes}
              end
            end
          end,
          {[], %{}, 0},
          TXPool
        )

      Enum.reverse(acc)
    catch
      :throw, {:choose, txs_packed} -> txs_packed
    end
  end

  def random(amount \\ 2)
  def random(0), do: []

  def random(amount) when is_integer(amount) and amount > 0 do
    match_spec = [{{:"$1", :"$2", :_, :_}, [], [{{:"$1", :"$2"}}]}]

    case :ets.select(TXPool, match_spec, amount) do
      :"$end_of_table" -> nil
      {[], _continuation} -> nil
      {entries, _continuation} -> entries
    end
  end

  def lowest_nonce(pk) do
    :ets.foldl(
      fn {{nonce, _hash}, txu, _tx_bytes, _reserved_ama}, lowest_nonce ->
        if txu.tx.signer == pk do
          cond do
            lowest_nonce == nil -> nonce
            nonce < lowest_nonce -> nonce
            true -> lowest_nonce
          end
        else
          lowest_nonce
        end
      end,
      nil,
      TXPool
    )
  end

  def highest_nonce() do
    Application.fetch_env!(:ama, :trainer_pk)
    |> highest_nonce()
  end

  def highest_nonce(pk) do
    :ets.foldl(
      fn {{nonce, _hash}, txu, _tx_bytes, _reserved_ama}, {highest_nonce, cnt} ->
        cond do
          txu.tx.signer == pk and (highest_nonce == nil or nonce > highest_nonce) ->
            {nonce, cnt + 1}

          txu.tx.signer == pk ->
            {highest_nonce, cnt + 1}

          true ->
            {highest_nonce, cnt}
        end
      end,
      {nil, 0},
      TXPool
    )
  end

  def size() do
    :ets.info(TXPool, :size)
  end

  @doc false
  def reserve_bytes(counter, amount, limit)
      when is_integer(amount) and amount >= 0 and is_integer(limit) and limit >= 0 do
    current = :atomics.get(counter, 1)

    if current + amount > limit do
      false
    else
      case :atomics.compare_exchange(counter, 1, current, current + amount) do
        :ok -> true
        _actual -> reserve_bytes(counter, amount, limit)
      end
    end
  end

  @doc false
  def release_bytes(counter, amount) when is_integer(amount) and amount >= 0 do
    :atomics.sub_get(counter, 1, amount)
  end

  @doc false
  def reserve_signer_ama(table, signer, amount, balance)
      when is_binary(signer) and is_integer(amount) and amount > 0 and is_integer(balance) and
             balance >= 0 do
    [count, reserved_ama] =
      :ets.update_counter(table, signer, [{2, 1}, {3, amount}], {signer, 0, 0})

    if reserved_ama <= balance do
      {:ok, count, reserved_ama}
    else
      {count, reserved_ama} = release_signer_ama(table, signer, amount)
      {:error, count, reserved_ama}
    end
  end

  @doc false
  def release_signer_ama(table, signer, amount)
      when is_binary(signer) and is_integer(amount) and amount > 0 do
    [count, reserved_ama] = :ets.update_counter(table, signer, [{2, -1}, {3, -amount}])
    zero_count? = count == 0
    zero_reservation? = reserved_ama == 0

    if count < 0 or reserved_ama < 0 or zero_count? != zero_reservation? do
      raise "TXPool signer reservation accounting underflow"
    end

    if zero_count? do
      :ets.delete_object(table, {signer, 0, 0})
    end

    {count, reserved_ama}
  end

  defp reserve_pool_bytes(amount), do: reserve_bytes(byte_counter(), amount, max_bytes())
  defp release_pool_bytes(amount), do: release_bytes(byte_counter(), amount)

  defp signer_has_capacity?(signer, amount, balance) do
    signer_reservation(signer).reserved_ama + amount <= balance
  end

  defp signer_full_error(txu, balance, amount) do
    reservation = signer_reservation(txu.tx.signer)

    %{
      error: :not_enough_txpool_balance,
      key: {txu.tx.nonce, txu.hash},
      balance: balance,
      reserved_ama: reservation.reserved_ama,
      required_ama: reservation.reserved_ama + amount
    }
  end

  defp pool_full_error() do
    %{error: :txpool_full, current_bytes: bytes(), max_bytes: max_bytes()}
  end

  defp delete_key(key) do
    case :ets.take(TXPool, key) do
      [{^key, txu, tx_bytes, reserved_ama}] ->
        release_pool_bytes(tx_bytes)
        release_signer_ama(TXPoolAccount, txu.tx.signer, reserved_ama)
        true

      [] ->
        false
    end
  end

  defp byte_counter() do
    :persistent_term.get({__MODULE__, :byte_counter})
  end
end
