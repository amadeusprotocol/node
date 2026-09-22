defmodule NodeANRTipMetadataTest do
  use ExUnit.Case, async: false

  test "tip-only updates preserve the last pruning floor" do
    pk = :crypto.strong_rand_bytes(48)

    try do
      NodeANR.set_tips(pk, nil, nil, 123)
      assert NodeANR.get_pruned_below_height(pk) == 123

      NodeANR.set_tips(pk, nil, nil)
      assert NodeANR.get_pruned_below_height(pk) == 123
    after
      :ets.delete(NODEANRHOT, pk)
    end
  end

  test "a peer cannot regress either stored tip" do
    pk = :crypto.strong_rand_bytes(48)
    high = %{header: %{height: 200}, hash: :crypto.strong_rand_bytes(32)}
    low = %{header: %{height: 199}, hash: :crypto.strong_rand_bytes(32)}

    try do
      NodeANR.set_tips(pk, high, high)
      NodeANR.set_tips(pk, low, low)
      hot = NodeANR.get_peer_hotdata(pk)
      assert hot.rooted.header.height == 200
      assert hot.temporal.header.height == 200
    after
      :ets.delete(NODEANRHOT, pk)
    end
  end

  test "a quorum-proved rooted tip wins at the same height" do
    pk = :crypto.strong_rand_bytes(48)
    old = %{header: %{height: 200}, hash: :crypto.strong_rand_bytes(32)}
    proved = old |> Map.put(:hash, :crypto.strong_rand_bytes(32)) |> Map.put(:quorum_proof, true)

    try do
      NodeANR.set_tips(pk, old, nil)
      NodeANR.set_tips(pk, proved, nil)
      assert NodeANR.get_peer_hotdata(pk).rooted == proved
      NodeANR.set_tips(pk, old, nil)
      assert NodeANR.get_peer_hotdata(pk).rooted == proved
    after
      :ets.delete(NODEANRHOT, pk)
    end
  end
end
