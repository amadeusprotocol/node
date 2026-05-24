defmodule NodeGenReassemblyGen do
  use GenServer

  def start_link(name \\ __MODULE__) do
    GenServer.start_link(__MODULE__, [name], name: name)
  end

  def init([name]) do
    state = %{name: name, reorg: %{}}
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
    put_in(state, [:reorg], reorg)
  end

  def handle_info(:tick, state) do
    state = clear_stale(state)
    :erlang.send_after(8000, self(), :tick)
    {:noreply, state}
  end

  def handle_info({:add_shard, key={pk, ts_nano, shard_total}, {peer_ip, version, shard_index, original_size}, shard}, state) do
    old_shards = get_in(state, [:reorg, key])
    cond do
      !old_shards -> {:noreply, put_in(state, [:reorg, key], %{shard_index=> shard})}
      old_shards == :spent -> {:noreply, state}

      map_size(old_shards) < (div(shard_total,2)-1) -> {:noreply, put_in(state, [:reorg, key, shard_index], shard)}

      true ->
        state = put_in(state, [:reorg, key], :spent)

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
