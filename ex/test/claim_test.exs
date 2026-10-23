defmodule ClaimTest do
  use ExUnit.Case, async: true

  test "a claim packs as height || entry_hash || root_contractstate || root_receipts" do
    claim = Claim.build(258, <<1::256>>, <<2::256>>, <<3::256>>)
    packed = Claim.pack(claim)
    assert packed == <<258::64-big, 1::256, 2::256, 3::256>>
    assert byte_size(packed) == 104
    assert Claim.hash(claim) == :crypto.hash(:sha256, packed)
    assert Claim.take(Map.put(claim, :aggsig, %{})) == claim
    assert Claim.for_height?(claim, 258)
    refute Claim.for_height?(claim, 259)
    refute Claim.valid?(%{claim | root_receipts: <<3::128>>})
    refute Claim.valid?(Map.delete(claim, :entry_height))
  end

  test "mmr leaves below the claim fork are entry hashes" do
    first = Claim.first_leaf_height()
    assert first in [88_100_000, 4_100_000]
    old = Claim.build(first - 1, <<1::256>>, <<2::256>>, <<3::256>>)
    new = Claim.build(first, <<1::256>>, <<2::256>>, <<3::256>>)
    assert Claim.mmr_leaf(old) == <<1::256>>
    assert Claim.mmr_leaf(new) == Claim.hash(new)
  end
end
