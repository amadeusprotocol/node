defmodule HTTP.RateLimiter do
  @table :http_rate_limiter

  def setup do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end
  end

  # Returns :ok or :rate_limited
  def check(ip, limit, window_ms) do
    now = System.monotonic_time(:millisecond)
    case :ets.lookup(@table, ip) do
      [{^ip, count, window_start}] when now - window_start < window_ms ->
        if count >= limit do
          :rate_limited
        else
          :ets.insert(@table, {ip, count + 1, window_start})
          :ok
        end
      _ ->
        :ets.insert(@table, {ip, 1, now})
        :ok
    end
  end
end
