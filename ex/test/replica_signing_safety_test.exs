defmodule ReplicaSigningSafetyTest do
  use ExUnit.Case, async: false

  setup do
    :ets.new(ReplicaGen, [:named_table, :public])
    old_config = :persistent_term.get({ReplicaGen, :config}, nil)
    keys = ["slash_lock", "block_lock", "block_proposal", "last_signed_height"]
    saved = Enum.map(keys, &{&1, MnesiaKV.get(ReplicaKV, &1)})
    Enum.each(keys, &MnesiaKV.delete(ReplicaKV, &1))
    :persistent_term.put({ReplicaGen, :config}, %{ready: true, my_id: 0, majority: 1})

    on_exit(fn ->
      :persistent_term.erase({ReplicaGen, :config})
      if old_config, do: :persistent_term.put({ReplicaGen, :config}, old_config)
      Enum.each(saved, fn {key, value} ->
        MnesiaKV.delete(ReplicaKV, key)
        if value, do: MnesiaKV.merge(ReplicaKV, key, value)
      end)
    end)
    :ok
  end

  test "peer majorities cannot bypass activation or a withdrawn self vote" do
    for size <- [3, 5] do
      :ets.delete_all_objects(ReplicaGen)
      majority = div(size, 2) + 1
      now = System.monotonic_time(:millisecond)
      :persistent_term.put({ReplicaGen, :config}, %{ready: true, my_id: 0, majority: majority})
      :ets.insert(ReplicaGen, [{:synced, true}, {:self_ack, 0}, {:self_ack_since, now}])
      for id <- 1..majority do
        :ets.insert(ReplicaGen, {{:peer, id}, %{acking: 0, seen: now}})
      end

      refute ReplicaGen.can_sign?()
      :ets.insert(ReplicaGen, {:self_ack_since, now - 2_000})
      assert ReplicaGen.can_sign?()
      :ets.insert(ReplicaGen, {:self_ack, nil})
      refute ReplicaGen.can_sign?()
      :ets.insert(ReplicaGen, {:self_ack, 1})
      refute ReplicaGen.can_sign?()
      :ets.insert(ReplicaGen, {:self_ack, 0})
      :ets.delete(ReplicaGen, :self_ack_since)
      refute ReplicaGen.can_sign?()
      :ets.insert(ReplicaGen, {:self_ack_since, now - 2_000})
      for id <- 1..majority do
        :ets.insert(ReplicaGen, {{:peer, id}, %{acking: 0, seen: now - 2_000}})
      end
      refute ReplicaGen.can_sign?()
    end
  end

  test "concurrent slash requests accept only one payload at each height" do
    for height <- 1..10 do
      results = race(for index <- 1..12, do: fn ->
        hash = :crypto.hash(:sha256, <<height::64, index::64>>)
        {hash, SpecialMeetingAttestGen.acquire_entry_sign_lock(height, hash)}
      end)
      assert [{hash, true}] = Enum.filter(results, &elem(&1, 1))
      assert ReplicaGen.my_slash_lock() == {height, hash}
      assert SpecialMeetingAttestGen.acquire_entry_sign_lock(height, hash)
      refute SpecialMeetingAttestGen.acquire_entry_sign_lock(height - 1, hash)
    end
  end

  test "adoption racing a slash request cannot accept conflicting reservations" do
    for height <- 1..10 do
      left = :crypto.hash(:sha256, <<height::64, 0>>)
      right = :crypto.hash(:sha256, <<height::64, 1>>)
      results = race([
        fn -> {left, SpecialMeetingAttestGen.acquire_entry_sign_lock(height, left)} end,
        fn -> {right, SpecialMeetingAttestGen.adopt_entry_sign_lock(height, right)} end
      ])
      assert [{hash, true}] = Enum.filter(results, &elem(&1, 1))
      assert ReplicaGen.my_slash_lock() == {height, hash}
    end
  end

  test "ordinary proposals and slash requests share the conflict check" do
    for height <- 1..10 do
      proposal = %{header: %{height: height}, txs: []}
      block_hash = Entry.header_hash(proposal.header)
      slash_hash = :crypto.hash(:sha256, <<height::64>>)
      results = race([
        fn -> {:block, ReplicaGen.prepare_block_proposal(proposal)} end,
        fn -> {:slash, SpecialMeetingAttestGen.acquire_entry_sign_lock(height, slash_hash)} end
      ])
      assert [{winner, true}] = Enum.filter(results, &elem(&1, 1))
      case winner do
        :block ->
          assert ReplicaGen.my_block_lock() == {height, block_hash}
          refute SpecialMeetingAttestGen.acquire_entry_sign_lock(height, slash_hash)
        :slash ->
          assert ReplicaGen.my_slash_lock() == {height, slash_hash}
          refute ReplicaGen.prepare_block_proposal(proposal)
      end
    end
  end

  test "competing proposal bodies cannot replace a reservation at the same height" do
    proposals = for index <- 1..12, do: %{header: %{height: 1, slot: index}, txs: []}
    results = race(for proposal <- proposals, do: fn ->
      {proposal, ReplicaGen.prepare_block_proposal(proposal)}
    end)
    assert [{proposal, true}] = Enum.filter(results, &elem(&1, 1))
    assert ReplicaGen.my_block_proposal() == proposal
    assert ReplicaGen.my_block_lock() == {1, Entry.header_hash(proposal.header)}
  end

  test "a proposal quorum wait does not hold the local signing lock" do
    :persistent_term.put({ReplicaGen, :config}, %{ready: true, my_id: 0, majority: 2})
    proposal = %{header: %{height: 1}, txs: []}
    hash = Entry.header_hash(proposal.header)
    task = Task.async(fn -> ReplicaGen.prepare_block_proposal(proposal) end)
    assert wait_for_block_lock(1, hash, 100)
    slash = Task.async(fn -> SpecialMeetingAttestGen.acquire_entry_sign_lock(1, hash) end)
    assert Task.await(slash, 1_000)
    assert Task.yield(task, 0) == nil
    :ets.insert(ReplicaGen, {{:peer, 1}, %{block_height: 1, block_hash: hash,
      block_proposal_ready: true, block_ready: false, seen: System.monotonic_time(:millisecond)}})
    assert Task.await(task, 1_000)
  end

  defp wait_for_block_lock(_height, _hash, 0), do: false
  defp wait_for_block_lock(height, hash, tries) do
    if ReplicaGen.my_block_lock() == {height, hash} do
      true
    else
      Process.sleep(10)
      wait_for_block_lock(height, hash, tries - 1)
    end
  end

  defp race(functions) do
    parent = self()
    tasks = Enum.map(functions, fn fun ->
      Task.async(fn ->
        send(parent, {:ready, self()})
        receive do :go -> fun.() end
      end)
    end)
    pids = for _ <- tasks do
      receive do {:ready, pid} -> pid after 1_000 -> flunk("worker did not start") end
    end
    Enum.each(pids, &send(&1, :go))
    Enum.map(tasks, &Task.await(&1, 10_000))
  end
end
