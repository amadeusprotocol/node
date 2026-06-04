defmodule API do
  def cached(key, ttl_ms, fun) do
    now = :os.system_time(1000)
    case :persistent_term.get({API.Cache, key}, nil) do
      {ts, val} when now - ts < ttl_ms -> val
      _ ->
        val = fun.()
        :persistent_term.put({API.Cache, key}, {now, val})
        val
    end
  end

  def maybe_b58(size, binary) do
    cond do
      size != byte_size(binary) -> Base58.decode(binary)
      binary == :binary.copy(<<"1">>, size) -> :binary.copy(<<0>>, size)
      true -> binary
    end
  end
end
