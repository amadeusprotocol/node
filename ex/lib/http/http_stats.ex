defmodule HTTP.Stats do
  #cost of HTTP requests per route: wall time and reductions (cpu work) of the
  #connection process while the handler runs. HTTP.Stats.top() in the console
  #row: {route, count, total_us, total_reductions, max_us, max_reductions}
  @max_routes 1_000

  def init() do
    :ets.new(HTTPStats, [:set, :named_table, :public, {:write_concurrency, true}, {:decentralized_counters, false}])
  end

  #a websocket upgrade runs its handler for the whole session: not a request
  def measure(%{headers: %{"upgrade" => "websocket"}}, fun), do: fun.()
  def measure(request, fun) do
    {_, reds} = Process.info(self(), :reductions)
    t0 = System.monotonic_time(:microsecond)
    result = fun.()
    us = System.monotonic_time(:microsecond) - t0
    {_, reds_after} = Process.info(self(), :reductions)
    record(route(request), us, reds_after - reds)
    result
  end

  defp record(route, us, reds) do
    [_, _, _, max_us, max_reds] = :ets.update_counter(HTTPStats, route,
      [{2, 1}, {3, us}, {4, reds}, {5, 0}, {6, 0}], {route, 0, 0, 0, 0, 0})
    #racy but monotonic enough for stats
    if us > max_us, do: :ets.update_element(HTTPStats, route, {5, us})
    if reds > max_reds, do: :ets.update_element(HTTPStats, route, {6, reds})
  end

  #hashes, addresses and numbers collapse to :x so a route is one row
  defp route(r) do
    path = (r[:path] || "") |> String.split("/")
      |> Enum.map_join("/", &if(byte_size(&1) > 16 or match?({_, ""}, Integer.parse(&1)), do: ":x", else: &1))
    route = "#{r[:method]} #{path}"
    if :ets.member(HTTPStats, route) or :ets.info(HTTPStats, :size) < @max_routes, do: route, else: "other"
  end

  def top(n \\ 20, by \\ :total_reductions) do
    :ets.tab2list(HTTPStats)
    |> Enum.map(fn {route, count, us, reds, max_us, max_reds} ->
      %{route: route, count: count, total_ms: div(us, 1000), avg_us: div(us, count),
        total_reductions: reds, avg_reductions: div(reds, count), max_us: max_us, max_reductions: max_reds}
    end)
    |> Enum.sort_by(& -Map.fetch!(&1, by))
    |> Enum.take(n)
  end

  def reset(), do: :ets.delete_all_objects(HTTPStats)
end
