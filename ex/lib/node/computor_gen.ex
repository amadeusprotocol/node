defmodule ComputorGen do
  use GenServer

  @batch_iterations 2000

  def start(type \\ nil) do
    send(__MODULE__, {:start, type})
  end

  def stop() do
    send(__MODULE__, :stop)
  end

  def start_link() do
    GenServer.start_link(__MODULE__, %{enabled: false}, name: __MODULE__)
  end

  def init(state) do
    :erlang.send_after(1000, self(), :tick)
    case Application.fetch_env!(:ama, :computor_type) do
      :trainer -> ComputorGen.start(:trainer)
      :default -> ComputorGen.start()
      _ -> nil
    end
    {:ok, state}
  end

  def handle_info(:tick, state) do
    next_ms = cond do
      !state[:enabled] -> 1000
      !FabricSyncAttestGen.isQuorumIsInEpoch() ->
        IO.puts "🔴 cannot compute: out_of_sync"
        1000
      true ->
        tick(state)
        0
    end
    :erlang.send_after(next_ms, self(), :tick)
    {:noreply, state}
  end

  def handle_info({:start, type}, state) do
    threads = Application.get_env(:ama, :computor_upow_threads, 0)
    IO.puts "🔢 computor enabled (type=#{inspect type}, upow_threads=#{if threads == 0, do: "auto", else: threads})"
    state = Map.put(state, :enabled, true)
    state = Map.put(state, :type, type)
    {:noreply, state}
  end

  def handle_info(:stop, state) do
    state = Map.put(state, :enabled, false)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  def tick(state) do
    pk = Application.fetch_env!(:ama, :trainer_pk)
    pop = Application.fetch_env!(:ama, :trainer_pop)
    threads = Application.get_env(:ama, :computor_upow_threads, 0)

    coins = DB.Chain.balance(pk)
    epoch = DB.Chain.epoch()
    segment_vr_hash = DB.Chain.segment_vr_hash()
    diff_bits = DB.Chain.diff_bits()
    hasExecCoins = coins >= BIC.Coin.to_cents(100)
    cond do
        is_nil(segment_vr_hash) -> :ok # epoch segment_vr not set yet; nothing to compute against

        (state.type == :trainer and !hasExecCoins) or state.type == nil ->
          # Compute to ourselves as a node: own pk is the computor (reward recipient).
          sol = UPOW.compute(epoch, EntryGenesis.signer(), EntryGenesis.pop(), pk, segment_vr_hash, diff_bits, @batch_iterations, threads)
          if sol do
            IO.puts "🔢 tensor matmul complete! broadcasting sol.."
            NodeGen.broadcast(%{op: :sol, sol: sol})
          end

        true ->
          sol = UPOW.compute(epoch, pk, pop, pk, segment_vr_hash, diff_bits, @batch_iterations, threads)
          if sol do
            sk = Application.fetch_env!(:ama, :trainer_sk)
            packed_tx = TX.build(sk, "Epoch", "submit_sol", [sol])
            %{hash: hash} = TX.unpack(packed_tx)
            IO.puts "🔢 tensor matmul complete! tx #{Base58.encode(hash)}"

            TXPool.insert(packed_tx)
            NodeGen.broadcast(NodeProto.event_tx(packed_tx))
          end
    end
    state
  end

  def set_emission_address(to_address) do
    sk = Application.fetch_env!(:ama, :trainer_sk)
    packed_tx = TX.build(sk, "Epoch", "set_emission_address", [to_address])
    TXPool.insert(packed_tx)
    NodeGen.broadcast(NodeProto.event_tx(packed_tx))
  end
end
