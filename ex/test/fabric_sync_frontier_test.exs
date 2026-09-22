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

    assert FabricSyncGen.root_hole_request(7, [<<2>>]) == %{
             height: 7,
             hashes: [<<2>>],
             e: true,
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

  test "frontier advertisements expire instead of pinning a permanent retry target" do
    advertisements = %{
      <<1>> => %{peer: %{pk: <<1>>, ip4: "10.0.0.1"}, height: 1_000_000, seen: 100},
      <<2>> => %{peer: %{pk: <<2>>, ip4: "10.0.0.2"}, height: 42, seen: 2_000}
    }

    assert FabricSyncGen.active_frontier_advertisements(advertisements, 2_100, 500)
           |> Map.keys() == [<<2>>]
  end

  test "trusted RPC leads frontier and bulk selection with other peers as fallback" do
    rpc = %{pk: <<1>>, ip4: "10.0.0.1"}
    advertiser = %{pk: <<2>>, ip4: "10.0.0.2"}
    relay = %{pk: <<3>>, ip4: "10.0.0.3"}
    alias_peer = %{pk: <<4>>, ip4: rpc.ip4}
    assert FabricSyncGen.select_frontier_peers([advertiser, relay], [rpc, alias_peer], advertiser.pk, 3, rpc.pk) ==
      [rpc, advertiser, relay]
    selected = FabricSyncGen.bulk_sync_peers([advertiser, rpc, relay, alias_peer], rpc.pk)
    assert length(selected) == 4
    assert Enum.take_every(selected, 2) == [rpc, rpc]
    assert MapSet.new(selected) == MapSet.new([rpc, advertiser, relay])

    # The preference never invents a peer: callers supply only online peers
    # whose retained history includes the requested height.
    assert FabricSyncGen.select_frontier_peers([advertiser], [relay], advertiser.pk, 3, rpc.pk) == [advertiser, relay]
    assert MapSet.new(FabricSyncGen.bulk_sync_peers([advertiser, relay], rpc.pk)) == MapSet.new([advertiser, relay])
  end
end
