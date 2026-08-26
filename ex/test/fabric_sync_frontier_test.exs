defmodule FabricSyncFrontierTest do
  use ExUnit.Case, async: true

  test "frontier requests always ask for local height plus one" do
    assert FabricSyncGen.frontier_height(41) == 42

    assert FabricSyncGen.frontier_request(42, [<<1>>]) == %{
             height: 42,
             hashes: [<<1>>],
             e: true,
             a: true,
             c: true
           }
  end

  test "advertising peer is prioritized and peers of any type can fill the hedge" do
    advertiser = %{pk: <<1>>, ip4: "10.0.0.1"}
    validator = %{pk: <<2>>, ip4: "10.0.0.2"}
    relay = %{pk: <<3>>, ip4: "10.0.0.3"}
    fallback = %{pk: <<4>>, ip4: "10.0.0.4"}

    selected =
      FabricSyncGen.select_frontier_peers(
        [validator, relay, advertiser],
        [fallback, relay, advertiser],
        advertiser.pk,
        3
      )

    assert hd(selected) == advertiser
    assert length(selected) == 3
    assert Enum.uniq_by(selected, & &1.pk) == selected
    assert validator in selected
    assert relay in selected
  end

  test "online peers are used when no peer advertised the next height" do
    peers = [
      %{pk: <<1>>, ip4: "10.0.0.1"},
      %{pk: <<2>>, ip4: "10.0.0.2"},
      %{pk: <<3>>, ip4: "10.0.0.3"}
    ]

    selected = FabricSyncGen.select_frontier_peers([], peers, nil, 3)

    assert MapSet.new(selected) == MapSet.new(peers)
  end
end
