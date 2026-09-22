defmodule FabricSyncRequestQueue do
  # The receiver's catchup bucket drains 37 messages every 3 seconds. Share
  # one paced budget across frontier, rooting and bulk work, keyed by IP just
  # like netguard (several identities can belong to the same host).
  # Leave one operation of headroom per refill; at quotas 75/75 this is one
  # message every 84ms (~12/s), each carrying up to 20 heights.
  @ops_per_refill max(1, div(min(NodeOps.quota(:catchup), NodeOps.quota(:catchup_reply)), 2) - 1)
  @send_interval_ms div(3_000 + @ops_per_refill - 1, @ops_per_refill)
  @retry_ms 1_000
  @pending_ttl_ms 5_000
  @max_pending_heights 4_096
  @batch_size 20

  def enqueue(queue, peers, requests, priority, now) do
    Enum.reduce(Enum.uniq_by(peers, & &1.ip4), queue, fn peer, queue ->
      bucket = Map.get(queue, peer.ip4, %{peer: peer, pending: %{}, recent: %{}, next_send: now})
      pending = Enum.reduce(requests, bucket.pending, fn request, pending ->
        # Exclusions are read from the DB when actually sent, after any queued
        # replies have arrived. Keep only the intent while waiting for a slot.
        request = Map.take(request, [:height, :e, :a, :c])
        item = %{request: request, priority: priority, seen: now}
        Map.update(pending, request.height, item, fn old ->
          flags = Map.merge(old.request, request, fn
            :height, _, height -> height
            _, a, b -> a || b
          end)
          %{item | request: flags, priority: min(old.priority, priority)}
        end)
      end)
      pending = if map_size(pending) > @max_pending_heights do
        pending |> Enum.sort_by(fn {height, item} -> {item.priority, height} end)
        |> Enum.take(@max_pending_heights) |> Map.new()
      else
        pending
      end
      Map.put(queue, peer.ip4, %{bucket | peer: peer, pending: pending})
    end)
  end

  # DB reads/encoding may delay dispatch after drain selected the batch. Start
  # the next slot at the actual send, so a new tip cannot spend that delay.
  def dispatched(queue, peer, requests, now) do
    Map.update!(queue, peer.ip4, fn bucket ->
      recent = Enum.reduce(requests, bucket.recent, &Map.put(&2, &1.height, now))
      %{bucket | recent: recent, next_send: now + @send_interval_ms}
    end)
  end

  # Pure scheduling: delayed timers never release a burst to "catch up". Lost
  # or empty replies can be retried, but repeated tip gossip cannot accelerate
  # retries for the same height. An alternate IP has its own independent slot.
  def drain(queue, now, rooted_height) do
    {queue, outgoing} = Enum.reduce(queue, {%{}, []}, fn {ip, bucket}, {queue, outgoing} ->
      pending = Map.filter(bucket.pending, fn {height, item} ->
        height > rooted_height and item.seen + @pending_ttl_ms > now
      end)
      recent = Map.filter(bucket.recent, fn {_, sent} -> sent + @retry_ms > now end)
      ready = if now >= bucket.next_send do
        pending
        |> Enum.reject(fn {height, _} -> Map.has_key?(recent, height) end)
        |> Enum.sort_by(fn {height, item} -> {item.priority, height} end)
        |> Enum.take(@batch_size)
      else
        []
      end
      {bucket, outgoing} = case ready do
        [] -> {%{bucket | pending: pending, recent: recent}, outgoing}
        _ ->
          heights = Enum.map(ready, &elem(&1, 0))
          requests = Enum.map(ready, fn {_, item} -> item.request end)
          bucket = %{bucket | pending: Map.drop(pending, heights),
            recent: Enum.reduce(heights, recent, &Map.put(&2, &1, now)), next_send: now + @send_interval_ms}
          {bucket, [{bucket.peer, requests} | outgoing]}
      end
      if bucket.pending == %{} and bucket.recent == %{} and bucket.next_send <= now do
        {queue, outgoing}
      else
        {Map.put(queue, ip, bucket), outgoing}
      end
    end)
    deadlines = Enum.map(queue, fn {_, bucket} ->
      if bucket.pending == %{} do
        Enum.reduce(bucket.recent, bucket.next_send, fn {_, sent}, deadline -> max(deadline, sent + @retry_ms) end)
      else
        Enum.reduce(bucket.pending, nil, fn {height, _}, deadline ->
          ready_at = case Map.fetch(bucket.recent, height) do
            {:ok, sent} -> max(bucket.next_send, sent + @retry_ms)
            :error -> bucket.next_send
          end
          if deadline == nil, do: ready_at, else: min(deadline, ready_at)
        end)
      end
    end)
    delay = case deadlines do
      [] -> nil
      _ -> max(0, Enum.min(deadlines) - now)
    end
    {queue, outgoing, delay}
  end
end
