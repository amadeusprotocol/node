defmodule API do
  #stale-while-revalidate with single-flight: a stale value is always served
  #immediately and exactly one caller kicks a background rebuild; only a cache
  #with no value at all (first boot) blocks, and only one process computes
  #while the rest wait on the lock (n concurrent scans once melted the RPC node)
  def cached(key, ttl_ms, fun) do
    case cache_read(key, ttl_ms) do
      {:fresh, val} -> val
      {:stale, val} ->
        rebuild_async(key, ttl_ms, fun)
        val
      :miss ->
        :global.trans({{API.Cache, key}, self()}, fn ->
          case cache_read(key, ttl_ms) do
            {:fresh, val} -> val
            _ ->
              val = fun.()
              :persistent_term.put({API.Cache, key}, {:os.system_time(1000), val})
              val
          end
        end)
    end
  end

  defp cache_read(key, ttl_ms) do
    now = :os.system_time(1000)
    case :persistent_term.get({API.Cache, key}, nil) do
      {ts, val} when now - ts < ttl_ms -> {:fresh, val}
      {_ts, val} -> {:stale, val}
      nil -> :miss
    end
  end

  #non-blocking: the lock loser returns instantly (the stale value is already
  #being served); the winner rechecks freshness and rebuilds off-request
  defp rebuild_async(key, ttl_ms, fun) do
    spawn(fn ->
      lock = {{API.Cache, key}, self()}
      if :global.set_lock(lock, [node()], 0) do
        try do
          case cache_read(key, ttl_ms) do
            {:fresh, _} -> :ok
            _ ->
              val = fun.()
              :persistent_term.put({API.Cache, key}, {:os.system_time(1000), val})
          end
        after
          :global.del_lock(lock, [node()])
        end
      end
    end)
  end

  def maybe_b58(size, binary) do
    cond do
      size != byte_size(binary) -> Base58.decode(binary)
      binary == :binary.copy(<<"1">>, size) -> :binary.copy(<<0>>, size)
      true -> binary
    end
  end
end
