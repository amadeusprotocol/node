defmodule ComputorGen do
  use GenServer

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
    state = cond do
      !state[:enabled] -> state
      !Application.fetch_env!(:ama, :testnet) ->
        IO.puts "Computor currently cannot find sols on mainnet due to difficulty. Do not waste CPU running it."
        state
      !FabricSyncAttestGen.isQuorumIsInEpoch() ->
        IO.puts "🔴 cannot compute: out_of_sync"
        state
      true ->
        tick(state)
    end
    :erlang.send_after(1000, self(), :tick)
    {:noreply, state}
  end

  def handle_info({:start, type}, state) do
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
    IO.puts "computor running #{DateTime.utc_now()}"
    pk = Application.fetch_env!(:ama, :trainer_pk)
    pop = Application.fetch_env!(:ama, :trainer_pop)

    coins = DB.Chain.balance(pk)
    epoch = DB.Chain.epoch()
    hasExecCoins = coins >= BIC.Coin.to_cents(100)
    cond do
        (state.type == :trainer and !hasExecCoins) or state.type == nil ->
          sol = UPOW.compute_for(epoch, EntryGenesis.signer(), EntryGenesis.pop(), pk, :crypto.strong_rand_bytes(96), 100)
          if sol do
            IO.puts "🔢 tensor matmul complete! broadcasting sol.."
            NodeGen.broadcast(:sol, :trainers, [sol])
          end

        true ->
          sol = UPOW.compute_for(epoch, pk, pop, pk, :crypto.strong_rand_bytes(96), 100)
          if sol do
            sk = Application.fetch_env!(:ama, :trainer_sk)
            packed_tx = TX.build(sk, "Epoch", "submit_sol", [sol])
            %{hash: hash} = TX.unpack(packed_tx)
            IO.puts "🔢 tensor matmul complete! tx #{Base58.encode(hash)}"

            TXPool.insert(packed_tx)
            NodeGen.broadcast(:txpool, :trainers, [[packed_tx]])
          end
    end
    state
  end

  def set_emission_address(to_address) do
    sk = Application.fetch_env!(:ama, :trainer_sk)
    packed_tx = TX.build(sk, "Epoch", "set_emission_address", [to_address])
    TXPool.insert(packed_tx)
    NodeGen.broadcast(:txpool, :trainers, [[packed_tx]])
  end
end
