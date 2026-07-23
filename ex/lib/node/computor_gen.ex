defmodule ComputorGen do
  use GenServer

  @batch_iterations 2000

  def start() do
    send(__MODULE__, :start)
  end

  def stop() do
    send(__MODULE__, :stop)
  end

  def start_link() do
    GenServer.start_link(__MODULE__, %{enabled: false}, name: __MODULE__)
  end

  def init(state) do
    :erlang.send_after(1000, self(), :tick)
    if Application.fetch_env!(:ama, :computor_enabled) do
      ComputorGen.start()
    end
    {:ok, state}
  end

  def handle_info(:tick, state) do
    {state, next_ms} = cond do
      !state[:enabled] -> {state, 1000}
      !FabricSyncAttestGen.isQuorumIsInEpoch() ->
        IO.puts "🔴 cannot compute: out_of_sync"
        {state, 1000}
      true ->
        tick(state)
    end
    :erlang.send_after(next_ms, self(), :tick)
    {:noreply, state}
  end

  def handle_info(:start, state) do
    threads = Application.get_env(:ama, :computor_upow_threads, 0)
    IO.puts "🔢 computor enabled (upow_threads=#{if threads == 0, do: "auto", else: threads})"
    state = Map.put(state, :enabled, true)
    {:noreply, state}
  end

  def handle_info(:stop, state) do
    state = Map.put(state, :enabled, false)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  def tick(state) do
    keys = Application.fetch_env!(:ama, :keys)
    threads = Application.get_env(:ama, :computor_upow_threads, 0)

    epoch = DB.Chain.epoch()
    segment_vr_hash = DB.Chain.segment_vr_hash()
    diff_bits = DB.Chain.diff_bits()
    {pick, underfunded_pks} = next_funded_key(keys, state[:key_idx] || 0)
    state = warn_underfunded(state, underfunded_pks)
    case pick do
      nil ->
        IO.puts "🔴 cannot compute: no key has at least 3 AMA for submit_sol"
        {state, 1000}

      {key, idx} ->
        sol = UPOW.compute(epoch, key.pk, key.pop, key.pk, segment_vr_hash, diff_bits, @batch_iterations, threads)
        if sol do
          packed_tx = TX.build(key.seed, "Epoch", "submit_sol", [sol])
          %{hash: hash} = TX.unpack(packed_tx)
          IO.puts "🔢 tensor matmul complete! tx #{Base58.encode(hash)} key #{Base58.encode(key.pk)}"

          TXPool.insert(packed_tx)
          NodeGen.broadcast(NodeProto.event_tx(packed_tx))
          {Map.put(state, :key_idx, idx + 1), 0}
        else
          {Map.put(state, :key_idx, idx), 0}
        end
    end
  end

  #3 AMA comfortably covers a submit_sol (1.2 AMA reserves + fee)
  @min_key_balance_flat 3 * 1_000_000_000

  defp next_funded_key(keys, idx) do
    n = length(keys)
    {funded, underfunded} = Enum.map(0..(n-1), fn(offset)->
      i = rem(idx + offset, n)
      {Enum.at(keys, i), i}
    end)
    |> Enum.split_with(fn({key, _i})-> DB.Chain.balance(key.pk) >= @min_key_balance_flat end)
    {List.first(funded), Enum.map(underfunded, fn({key, _i})-> key.pk end) |> Enum.sort()}
  end

  defp warn_underfunded(state, underfunded_pks) do
    if underfunded_pks != state[:underfunded] do
      Enum.each(underfunded_pks, & IO.puts "🔴 key #{Base58.encode(&1)} has less than 3 AMA, skipping")
    end
    Map.put(state, :underfunded, underfunded_pks)
  end
end
