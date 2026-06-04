defmodule NodeGenNetguard do
  @max_frames_per_6_sec 40_000
  @max_ips_per_shard 10_000

  def frame_ok(peer_ip) do
    phash = :erlang.phash2(peer_ip, 8)
    tbl = :"NODENetGuardTotalFrames#{phash}"
    if :ets.lookup(tbl, peer_ip) == [] and :ets.info(tbl, :size) >= @max_ips_per_shard do
      true
    else
      :ets.update_counter(tbl, peer_ip, 1, {peer_ip, 0}) < @max_frames_per_6_sec
    end
  end

  def op_ok(peer_ip, op) do
    if quota = NodeOps.quota(op) do
      phash = :erlang.phash2(peer_ip, 8)
      tbl = :"NODENetGuardPer6Seconds#{phash}"
      if :ets.lookup(tbl, {peer_ip, op}) == [] and :ets.info(tbl, :size) >= @max_ips_per_shard do
        true
      else
        :ets.update_counter(tbl, {peer_ip, op}, 1, {{peer_ip, op}, 0}) < quota
      end
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
      step = trunc((NodeOps.quota(op) || 0) / 2)
      ctr = :ets.update_counter(:"NODENetGuardPer6Seconds#{idx}", {peer_ip, op}, {2, -step, 0, 0})
      ctr == 0 && :ets.delete(:"NODENetGuardPer6Seconds#{idx}", {peer_ip, op})
    end, nil, :"NODENetGuardPer6Seconds#{idx}")
  end
end
