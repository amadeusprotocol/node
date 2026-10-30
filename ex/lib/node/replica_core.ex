defmodule ReplicaCore do
  #pure replica decisions, no I/O: ReplicaGen feeds it clocks, peer rows,
  #sync samples and messages, and the partition simulator
  #(test/replica_sim_test.exs) drives the very same functions through hostile
  #network schedules.
  #
  #peer row: %{id, acking, synced, seen}
  #
  #LEADERSHIP is a lease (majority acks fresher than @ack_ttl_ms). it only
  #decides who may START a signature; it is not what keeps signatures unique:
  #a leader cut off from the group keeps its acks for up to @ack_ttl_ms while
  #the group elects a successor, and on 2026-10-29 both signed heights
  #88971608..610 differently.
  #
  #PER-HEIGHT CONSENSUS. what the pack signs at a height (an entry it
  #produces, a slash entry, an entry it attests) is decided by single-decree
  #Paxos for that height, run by the leader, Multi-Paxos style:
  #  * ballot {round, replica_id}, totally ordered. a leader PREPAREs once per
  #    term; a majority PROMISEs and reports what each already accepted
  #  * at a height, the leader must propose the value with the highest ballot
  #    any promise reported there; only when none was reported may it propose
  #    its own. heights below the reported window are closed
  #  * ACCEPT stores {hash, ballot, kind} for the height, durably, and for an
  #    entry that exists nowhere but in the group (our own unsigned production
  #    or slash candidate) only while the acceptor stores that entry itself
  #  * once a majority accepted it in one ballot the value is chosen: only then
  #    may anything be signed at that height
  #two different values can never both be chosen at a height, every successor
  #finds the chosen one (any two majorities share an acceptor) and can always
  #carry on with it (that acceptor stores the entry). conflicting proposals
  #left by interrupted leaders are settled by the next higher ballot.
  #
  #acceptor state: %{promised: ballot, accepted: %{height => %{hash, b, kind}}}
  #  accepted is kept for the newest @window heights; the chain only moves
  #  forward, so a height that falls below the window is closed for good

  @ack_ttl_ms 1_000          #producing needs majority acks fresher than this
  @silence_timeout_ms 2_000  #peer counts as gone after this much silence
  @ack_cooldown_ms 2_500     #quiet gap between acking two different peers
  @demote_after 3            #consecutive unsynced samples before demotion
  @window 16                 #accepted heights kept per acceptor

  def ack_ttl_ms(), do: @ack_ttl_ms
  def silence_timeout_ms(), do: @silence_timeout_ms
  def ack_cooldown_ms(), do: @ack_cooldown_ms
  def window(), do: @window

  def majority(group_size), do: div(group_size, 2) + 1

  #leadership

  #promote immediately, demote only after @demote_after consecutive unsynced
  #samples so a transient blip cannot flap leadership
  def next_sync(raw, synced, streak) do
    cond do
      raw -> {true, 0}
      streak + 1 >= @demote_after -> {false, streak + 1}
      true -> {synced, streak + 1}
    end
  end

  #leadership candidates: fresh AND self-reporting synced. an unsynced member
  #(self included) is never endorsed; with no synced member at all the target
  #goes nil and nobody signs until someone catches up
  def desired_target(my_id, synced, peer_rows, now) do
    ids = for r <- peer_rows, r.synced and now - r.seen <= @silence_timeout_ms, do: r.id
    ids = if synced do [my_id | ids] else ids end
    case ids do [] -> nil; ids -> Enum.min(ids) end
  end

  #never endorse two different leaders within one freshness window: any target
  #switch goes through a silent cooldown first. returns {target, last_change}
  def update_ack_target(target, last_change, desired, now) do
    cond do
      target == desired -> {target, last_change}
      target != nil -> {nil, now}
      last_change == nil or now - last_change >= @ack_cooldown_ms -> {desired, now}
      true -> {target, last_change}
    end
  end

  #self ack plus majority-fresh peer acks, and synced ourselves
  def leader?(my_id, majority, self_ack, synced, peer_rows, now) do
    self = if self_ack == my_id do 1 else 0 end
    fresh = Enum.count(peer_rows, & &1.acking == my_id and now - &1.seen <= @ack_ttl_ms)
    synced and self + fresh >= majority
  end

  #per-height consensus: acceptor

  @zero_ballot {0, 0}
  def zero_ballot(), do: @zero_ballot

  def new_acceptor(), do: %{promised: @zero_ballot, accepted: %{}}

  #entries a successor may have to finish from the group alone: accepted only
  #while stored. our own production and slash candidates, and an outside
  #carrier's slash entry we sign (its carrier may be gone before it lands)
  def needs_entry?(kind), do: kind in [:produce, :slash, :slash_ext]

  #an equal ballot is promised again: the first promise may have been lost,
  #and the proposer's retransmitted prepare must still be answered
  #replies are the wire messages themselves (the sender adds :from).
  #ballots stay {round, replica_id} tuples: term order compares them round
  #first, which a map would not
  def on_prepare(acc, ballot) do
    if ballot >= acc.promised do
      acc = %{acc | promised: ballot}
      {acc, %{op: :promise, ballot: ballot, accepted: acc.accepted}}
    else
      {acc, %{op: :nack, ballot: ballot, promised: acc.promised}}
    end
  end

  #holds_entry: the acceptor durably stores the entry the hash names
  def on_accept(acc, ballot, height, hash, kind, holds_entry) do
    cond do
      ballot < acc.promised -> {acc, %{op: :nack, ballot: ballot, promised: acc.promised}}
      height < open_floor(acc.accepted) -> {acc, %{op: :closed, ballot: ballot, height: height}}
      needs_entry?(kind) and !holds_entry -> {acc, %{op: :need_entry, ballot: ballot, height: height, hash: hash}}
      true ->
        accepted = Map.put(acc.accepted, height, %{hash: hash, b: ballot, kind: kind})
        {%{promised: ballot, accepted: prune(accepted)}, %{op: :accepted, ballot: ballot, height: height, hash: hash}}
    end
  end

  #lowest height still open: the newest @window accepted heights
  def open_floor(accepted) when map_size(accepted) == 0, do: 0
  def open_floor(accepted), do: Enum.max(Map.keys(accepted)) - @window + 1

  defp prune(accepted) do
    f = open_floor(accepted)
    Map.reject(accepted, fn({h, _})-> h < f end)
  end

  #per-height consensus: proposer

  #a ballot above every round seen, ours
  def next_ballot(max_round_seen, my_id), do: {max_round_seen + 1, my_id}

  #what the leader may propose at height, given the accepted windows of a
  #majority of promises (its own included) and what it proposed itself under
  #its current ballot:
  #  :closed        height is below the window: never sign it
  #  %{hash, kind}  the highest-ballot value accepted there (possibly
  #                 chosen): the ONLY value it may propose there
  #  :free          nothing accepted there: its own value
  def bound(promised_windows, height) do
    floor = promised_windows |> Enum.map(&open_floor/1) |> Enum.max(fn -> 0 end)
    values = for w <- promised_windows, v = w[height], v != nil, do: v
    cond do
      height < floor -> :closed
      values == [] -> :free
      true ->
        Map.take(Enum.max_by(values, & &1.b), [:hash, :kind])
    end
  end

  #a majority (self included) accepted the value under this ballot
  def chosen?(acks, majority), do: MapSet.size(acks) >= majority
end
