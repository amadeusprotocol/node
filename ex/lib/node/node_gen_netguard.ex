defmodule NodeGenNetguard do
  @max_frames_per_6_sec 40_000
  @max_msg_per_6_sec %{
    new_phone_who_dis: 20,
    new_phone_who_dis_reply: 20,
    get_peer_anrs: 10,
    get_peer_anrs_reply: 10,
    ping: 30,
    ping_reply: 30,
    special_business: 200,
    special_business_reply: 200,
    catchup: 50,
    catchup_reply: 50,
    event_tip: 60,
    event_entry: 60,
    event_tx: 8000,
    event_attestation: 8000,
    solicit_entry: 2,
    sell_sol: 10_000,
  }
  @msg_ops Enum.into(@max_msg_per_6_sec, %{}, & {elem(&1,0), true})

  def frame_ok(peer_ip) do
    phash = :erlang.phash2(peer_ip, 8)
    counter = :ets.update_counter(:"NODENetGuardTotalFrames#{phash}", peer_ip, 1, {peer_ip, 0})
    counter < @max_frames_per_6_sec
  end

  def op_ok(peer_ip, op) do
    if @msg_ops[op] do
      phash = :erlang.phash2(peer_ip, 8)
      counter = :ets.update_counter(:"NODENetGuardPer6Seconds#{phash}", {peer_ip, op}, 1, {{peer_ip, op}, 0})
      counter < @max_msg_per_6_sec[op]
    end
  end

  @handshake_attempt_cooldown_ms 3000
  def handshake_attempt_ok(peer_ip) do
    now = :os.system_time(1000)
    case :ets.lookup(NODEHandshakeAttempt, peer_ip) do
      [{^peer_ip, last}] when now - last < @handshake_attempt_cooldown_ms -> false
      _ ->
        :ets.insert(NODEHandshakeAttempt, {peer_ip, now})
        true
    end
  end

  def decrement_buckets(idx) do
    step = trunc(@max_frames_per_6_sec / 2)
    :ets.foldl(fn({peer_ip, _}, _)->
      ctr = :ets.update_counter(:"NODENetGuardTotalFrames#{idx}", peer_ip, {2, -step, 0, 0})
      ctr == 0 && :ets.delete(:"NODENetGuardTotalFrames#{idx}", peer_ip)
    end, nil, :"NODENetGuardTotalFrames#{idx}")

    :ets.foldl(fn({{peer_ip, op}, _}, _)->
      step = trunc(@max_msg_per_6_sec[op] / 2)
      ctr = :ets.update_counter(:"NODENetGuardPer6Seconds#{idx}", {peer_ip, op}, {2, -step, 0, 0})
      ctr == 0 && :ets.delete(:"NODENetGuardPer6Seconds#{idx}", {peer_ip, op})
    end, nil, :"NODENetGuardPer6Seconds#{idx}")
  end
end
