defmodule NodeGenReassemblyGen do
  use GenServer

  @max_total_states 4096
  @max_inflight_per_pk 4096
  @future_tolerance_nano 30_000_000_000

  def start_link(name \\ __MODULE__) do
    GenServer.start_link(__MODULE__, [name], name: name)
  end

  def init([name]) do
    state = %{name: name, reorg: %{}, per_pk: %{}}
    :erlang.send_after(8000, self(), :tick)
    {:ok, state}
  end

  def clear_stale(state) do
    ts_nano = :os.system_time(:nanosecond)
    threshold_min = ts_nano - 8_000_000_000
    threshold_max = ts_nano + 30_000_000_000
    reorg = state.reorg
    |> Map.filter(fn {{_pk, ts_nano, _shard_total}, _value} ->
        ts_nano > threshold_min and ts_nano < threshold_max
    end)
    per_pk = Enum.reduce(reorg, %{}, fn {{pk,_,_}, v}, acc ->
      if v == :spent, do: acc, else: Map.update(acc, pk, 1, &(&1 + 1))
    end)
    %{state | reorg: reorg, per_pk: per_pk}
  end

  def handle_info(:tick, state) do
    state = clear_stale(state)
    :erlang.send_after(8000, self(), :tick)
    {:noreply, state}
  end

  def handle_info({:add_shard, key={_pk, ts_nano, shard_total}, {peer_ip, version, shard_index, original_size}, shard}, state) do
    now_nano = :os.system_time(:nanosecond)
    cond do
      not is_integer(shard_total) or shard_total <= 0 -> {:noreply, state}
      not is_integer(original_size) or original_size <= 0 -> {:noreply, state}
      not is_integer(shard_index) or shard_index < 0 or shard_index >= shard_total -> {:noreply, state}
      not is_integer(ts_nano) or ts_nano > now_nano + @future_tolerance_nano -> {:noreply, state}
      shard_total > div(original_size + 1023, 1024) * 2 + 8 -> {:noreply, state}
      map_size(state.reorg) >= @max_total_states and not Map.has_key?(state.reorg, key) -> {:noreply, state}
      true -> do_add_shard(key, peer_ip, version, shard_index, original_size, shard, state)
    end
  end

  def handle_info(_, state), do: {:noreply, state}

  defp do_add_shard(key={pk, ts_nano, shard_total}, peer_ip, version, shard_index, original_size, shard, state) do
    old_shards = get_in(state, [:reorg, key])
    cond do
      !old_shards ->
        cur = Map.get(state.per_pk, pk, 0)
        if cur >= @max_inflight_per_pk do
          {:noreply, state}
        else
          state = put_in(state, [:reorg, key], %{shard_index => shard})
          {:noreply, %{state | per_pk: Map.put(state.per_pk, pk, cur + 1)}}
        end
      old_shards == :spent -> {:noreply, state}

      is_map_key(old_shards, shard_index) -> {:noreply, state}

      map_size(old_shards) < (div(shard_total,2)-1) -> {:noreply, put_in(state, [:reorg, key, shard_index], shard)}

      true ->
        state = put_in(state, [:reorg, key], :spent)
        per_pk = Map.update(state.per_pk, pk, 0, &max(&1 - 1, 0))
        state = %{state | per_pk: per_pk}

        shards = :maps.to_list(old_shards) ++ [{shard_index, shard}]

        try do
          r = ReedSolomonEx.create_resource(div(shard_total,2), div(shard_total,2), 1024)
          payload = ReedSolomonEx.decode_shards(r, shards, shard_total, original_size)
          :erlang.spawn(fn()->
            try do
              NodeGenSocketGen.proc_payload(peer_ip, pk, version, ts_nano, payload)
            catch
              _,_ -> nil
            end
          end)
        catch
          e,r -> IO.inspect {:msg_reassemble_failed, e, r, __STACKTRACE__}
        end
        {:noreply, state}
    end
  end
end
