defmodule ClaimTest do
  use ExUnit.Case, async: true

  test "a claim packs as height || entry_hash || root_contractstate || root_receipts" do
    claim = %{entry_height: 258, entry_hash: <<1::256>>, root_contractstate: <<2::256>>, root_receipts: <<3::256>>}
    packed = Claim.pack(claim)
    assert packed == <<258::64-big, 1::256, 2::256, 3::256>>
    assert byte_size(packed) == 104
    assert Claim.hash(claim) == :crypto.hash(:sha256, packed)
    assert Claim.mmr_leaf(claim) == Claim.hash(claim)
    assert Claim.take(Map.put(claim, :aggsig, %{})) == claim
  end

  test "a legacy claim keeps mutations_hash as its hash and the entry hash as its leaf" do
    legacy = %{entry_hash: <<1::256>>, mutations_hash: <<2::256>>}
    assert Claim.pack(legacy) == <<1::256, 2::256>>
    assert Claim.hash(legacy) == <<2::256>>
    assert Claim.mmr_leaf(legacy) == <<1::256>>
    assert Claim.valid?(legacy)
    refute Claim.valid?(%{legacy | mutations_hash: <<2::128>>})
    assert Claim.take(Map.put(legacy, :signer, <<>>)) == legacy
  end

  test "build and for_height? pick the shape of the height" do
    fork = RDBProtocol.forkheight()
    if fork > 0 do
      assert Claim.build(fork - 1, <<1::256>>, <<2::256>>, <<3::256>>, <<4::256>>) == %{entry_hash: <<1::256>>, mutations_hash: <<2::256>>}
      assert Claim.for_height?(%{entry_hash: <<1::256>>, mutations_hash: <<2::256>>}, fork - 1)
    end
    if fork < 0x7FFF_FFFF_FFFF_FFFF do
      claim = Claim.build(fork, <<1::256>>, <<2::256>>, <<3::256>>, <<4::256>>)
      assert claim == %{entry_height: fork, entry_hash: <<1::256>>, root_contractstate: <<3::256>>, root_receipts: <<4::256>>}
      assert Claim.for_height?(claim, fork)
      refute Claim.for_height?(claim, fork + 1)
      refute Claim.for_height?(%{entry_hash: <<1::256>>, mutations_hash: <<2::256>>}, fork)
    end
  end
end
