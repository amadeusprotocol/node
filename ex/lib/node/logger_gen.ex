defmodule LoggerGen do
  use GenServer

  def start() do
    send(__MODULE__, :start)
  end

  def stop() do
    send(__MODULE__, :stop)
  end

  def start_link() do
    GenServer.start_link(__MODULE__, %{enabled: true}, name: __MODULE__)
  end

  def init(state) do
    :erlang.send_after(1000, self(), :tick)
    {:ok, state}
  end

  def handle_info(:tick, state) do
    state = if state[:enabled] do try do __MODULE__.tick(state) catch _,_ -> state end else state end
    :erlang.send_after(6000, self(), :tick)
    {:noreply, state}
  end

  def handle_info(:start, state) do
    state = Map.put(state, :enabled, true)
    {:noreply, state}
  end

  def handle_info(:stop, state) do
    state = Map.put(state, :enabled, false)
    {:noreply, state}
  end

  def tick(state) do
    entry_rooted = DB.Chain.rooted_tip_entry()
    rooted_height = entry_rooted.header.height

    entry = DB.Chain.tip_entry()
    height = entry.header.height
    slot = entry.header.slot
    txpool_size = :ets.info(TXPool, :size)

    {vals, peers} = NodeANR.handshaked_and_online()
    peer_cnt = length(vals++peers) + 1

    pk = Application.fetch_env!(:ama, :trainer_pk)
    coins = DB.Chain.balance(pk)

    trainers = DB.Chain.validators_for_height(Entry.height(entry)+1)

    #Moneybag mean the money in my bag
    #Moneybag mean the money in the bag
    #Moneyround mean i roll wit da money
    isTrainer = if pk in trainers do "💰" else "🪙" end

    isSynced = FabricSyncAttestGen.isQuorumSyncedOffBy1() || Application.fetch_env!(:ama, :testnet)
    highest_height = max(FabricSyncAttestGen.highestTemporalHeight() || height, height)
    score = API.Epoch.score(pk)[:score] || 0

    if !isSynced do
      IO.puts "⛓️  #{height} / #{highest_height} R: #{height-rooted_height} | T: #{txpool_size} P: #{peer_cnt} 🔴 NOT-SYNCED #{Base58.encode(pk)}"
    else
      IO.puts "⛓️  #{height} / #{highest_height} R: #{height-rooted_height} | T: #{txpool_size} P: #{peer_cnt} S: #{score} | #{Base58.encode(pk)} #{isTrainer} #{coins_2dp(coins)}"
    end

    state
  end

  defp coins_2dp(flat) when is_integer(flat) do
    hundredths = div(flat + 9_999_999, 10_000_000)
    "#{div(hundredths, 100)}.#{String.pad_leading(Integer.to_string(rem(hundredths, 100)), 2, "0")}"
  end
end
