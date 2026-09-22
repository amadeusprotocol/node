defmodule ReplicaElectionTest do
  use ExUnit.Case, async: true

  test "leader requires an exact chain state shared by a replica majority" do
    hash_a = :binary.copy(<<1>>, 32)
    hash_b = :binary.copy(<<2>>, 32)
    root = :binary.copy(<<3>>, 32)
    current = %{temporal_height: 20, temporal_hash: hash_a, rooted_height: 19, rooted_hash: root}
    fork = %{current | temporal_hash: hash_b}
    one_behind = %{current | temporal_height: 19}

    assert ReplicaGen.choose_leader([{2, current}, {1, current}, {0, one_behind}], 2) == 1
    assert ReplicaGen.choose_leader([{0, current}, {1, fork}, {2, one_behind}], 2) == nil
  end

  test "one divergent election sample does not abandon a live leader" do
    state = %{ack_target: 1, pending_ack_target: nil, pending_ack_streak: 0}
    candidates = MapSet.new([1, 2])

    assert {1, state} = ReplicaGen.stabilize_ack_target(state, nil, candidates)
    assert state.pending_ack_target == nil
    assert state.pending_ack_streak == 1

    assert {nil, state} = ReplicaGen.stabilize_ack_target(state, nil, candidates)
    assert state.pending_ack_target == nil
    assert state.pending_ack_streak == 0
  end

  test "a vanished leader is abandoned without election hysteresis" do
    state = %{ack_target: 1, pending_ack_target: nil, pending_ack_streak: 0}

    assert {nil, state} = ReplicaGen.stabilize_ack_target(state, nil, MapSet.new([2]))
    assert state.pending_ack_streak == 0
  end

  test "pre-sign locks and signed-body readiness are separate acknowledgements" do
    now = 10_000
    hash = :binary.copy(<<1>>, 32)
    peer = %{
      block_height: 50,
      block_hash: hash,
      block_proposal_ready: true,
      block_ready: false,
      seen: now
    }

    assert ReplicaGen.block_state_ack?(peer, 50, hash, :proposal, now)
    refute ReplicaGen.block_state_ack?(peer, 50, hash, :signed, now)
    assert ReplicaGen.block_state_ack?(%{peer | block_ready: true}, 50, hash, :signed, now)
    assert ReplicaGen.block_state_ack?(%{peer | block_proposal_ready: false, block_ready: true}, 50, hash, :proposal, now)
    refute ReplicaGen.block_state_ack?(%{peer | block_height: 51}, 50, hash, :proposal, now)
  end

  test "only fresh peer locks with a recoverable body raise the production high-water mark" do
    now = 10_000
    peer = %{
      block_height: 50,
      block_proposal_ready: false,
      block_ready: false,
      seen: now
    }

    assert ReplicaGen.peer_recoverable_block_height(peer, now) == 0
    assert ReplicaGen.peer_recoverable_block_height(%{peer | block_proposal_ready: true}, now) == 50
    assert ReplicaGen.peer_recoverable_block_height(%{peer | block_ready: true}, now) == 50
    assert ReplicaGen.peer_recoverable_block_height(%{peer | block_proposal_ready: true, seen: now - 2_001}, now) == 0
  end

  test "single-node mode treats signed-body replication as complete" do
    assert :persistent_term.get({ReplicaGen, :config}, nil) == nil

    entry = %{header: %{height: 1}, hash: :binary.copy(<<1>>, 32)}
    assert ReplicaGen.replicate_block(entry)
  end

  test "a block lock stops pending once its canonical height is reached" do
    locked_hash = :binary.copy(<<1>>, 32)
    other_hash = :binary.copy(<<2>>, 32)

    assert ReplicaGen.block_lock_chain_status(50, locked_hash, 49, nil) == :pending
    assert ReplicaGen.block_lock_chain_status(50, locked_hash, 50, locked_hash) == :included
    assert ReplicaGen.block_lock_chain_status(50, locked_hash, 50, other_hash) == :superseded
    assert ReplicaGen.block_lock_chain_status(50, locked_hash, 51, nil) == :superseded
  end

  test "an exact attestation lock echo is valid before the local apply commits" do
    entry_hash = :binary.copy(<<1>>, 32)
    muts_hash = :binary.copy(<<2>>, 32)
    lock = {50, entry_hash, muts_hash}

    assert ReplicaGen.attest_lock_advertisement_valid?(50, entry_hash, muts_hash, lock, nil, nil)

    refute ReplicaGen.attest_lock_advertisement_valid?(
      50, entry_hash, :binary.copy(<<3>>, 32), lock, nil, nil)

    entry = %{header: %{height: 50}}
    assert ReplicaGen.attest_lock_advertisement_valid?(50, entry_hash, muts_hash,
      {49, entry_hash, muts_hash}, entry, muts_hash)
  end

  test "a newly selected leader waits beyond the stale acknowledgement window" do
    refute ReplicaGen.leadership_activation_elapsed?(10_000, 11_499, 1_500)
    assert ReplicaGen.leadership_activation_elapsed?(10_000, 11_500, 1_500)
  end

  test "proposal repair only targets peers that are still missing a pending height" do
    hash = :binary.copy(<<1>>, 32)

    assert ReplicaGen.proposal_repair_needed?(49, 50, 49, 49, hash, false, hash)
    assert ReplicaGen.proposal_repair_needed?(49, 50, 49, 50, hash, false, hash)

    refute ReplicaGen.proposal_repair_needed?(50, 50, 49, 49, hash, false, hash)
    refute ReplicaGen.proposal_repair_needed?(49, 50, 50, 49, hash, false, hash)
    refute ReplicaGen.proposal_repair_needed?(49, 50, 49, 50, hash, true, hash)
  end

  test "slash proposals are reserved for special-meeting recovery" do
    slash_tx = %{
      tx: %{
        action: %{contract: "Epoch", function: "slash_trainer", args: []}
      }
    }

    normal_tx = put_in(slash_tx, [:tx, :action, :function], "set_emission_address")

    assert ReplicaGen.slash_block_proposal?(%{txs: [slash_tx]})
    refute ReplicaGen.slash_block_proposal?(%{txs: [normal_tx]})
    refute ReplicaGen.slash_block_proposal?(%{txs: []})
  end

  test "leadership loss discards an in-flight special meeting" do
    state = %{slash_trainer: %{state: :gather_entry_sigs}, unrelated: :kept}

    assert SpecialMeetingGen.retain_motion_leadership(state, true) == state
    assert SpecialMeetingGen.retain_motion_leadership(state, false) == %{unrelated: :kept}
  end
end
