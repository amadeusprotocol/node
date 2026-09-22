defmodule NodeANRQuorumTest do
  use ExUnit.Case, async: true

  test "height threshold uses the full validator denominator" do
    observations = [
      %{height: 100},
      %{height: 99},
      %{height: 98}
    ]

    assert NodeANR.reached_by_count(observations, :height, 3) == 98
    assert NodeANR.reached_by_count(observations, :height, 4) == 0
  end

  test "tip gossip remains a sync target but cannot inhibit production without a received entry" do
    local_hash = :crypto.strong_rand_bytes(32)
    local_tip = %{hash: local_hash, header: %{height: 41}}
    advertised = %{hash: :crypto.strong_rand_bytes(32), header: %{height: 42}}

    assert NodeANR.decision_temporal_height(advertised, local_tip) == nil

    received = Map.merge(advertised, %{known_entry: true, connects_to: local_hash})
    assert NodeANR.decision_temporal_height(received, local_tip) == 42

    quorum_entry = Map.merge(advertised, %{quorum_entry: true, connects_to: local_hash})
    assert NodeANR.decision_temporal_height(quorum_entry, local_tip) == 42

    wrong_parent = %{received | connects_to: :crypto.strong_rand_bytes(32)}
    assert NodeANR.decision_temporal_height(wrong_parent, local_tip) == nil
  end

  test "a quorum certificate works for nodes with no local validator keys" do
    validator = :crypto.strong_rand_bytes(48)
    relay = %{pk: :crypto.strong_rand_bytes(48)}

    assert FabricSyncAttestGen.quorum_counts([validator], [], [], [relay], 3, true) == {3, 3}
    assert FabricSyncAttestGen.quorum_counts([validator], [], [], [relay], 3, false) == {2, 3}
  end

  test "a rooted tip without a quorum proof is false rather than an exception" do
    refute NodeANR.rooted_quorum_tip?(%{header: %{height: 10}}, 9)
    refute NodeANR.rooted_quorum_tip?(%{header: %{height: 10}, quorum_proof: nil}, 9)
    assert NodeANR.rooted_quorum_tip?(%{header: %{height: 10}, quorum_proof: true}, 9)
  end
end
