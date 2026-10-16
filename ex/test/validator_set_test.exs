defmodule ValidatorSetTest do
  use ExUnit.Case, async: true

  test "1001 roster slots survive removals with canonical variable-length masks" do
    roster = for i <- 0..1000, do: <<i::384>>
    set = ValidatorSet.normalize(roster)
    assert byte_size(set.mask_active) == 126
    assert :binary.last(set.mask_active) == 128
    active = Enum.reject(Enum.with_index(roster), fn {_, i} -> i in [0, 255, 256, 999] end)
    mask = Enum.reduce(active, <<0::1008>>, fn {_, i}, acc -> Util.set_bit(acc, i) end)
    set = %{set | mask_active: mask}
    agg = %{BLS12AggSig.new_padded(set) | mask: mask}
    assert ValidatorSet.roster(set) == roster
    assert ValidatorSet.active(set) == Enum.map(active, &elem(&1, 0))
    assert {:ok, signers} = BLS12AggSig.validate(agg, set)
    assert List.last(signers) == List.last(roster)
    assert BLS12AggSig.score(agg) == 1.0
    assert BLS12AggSig.quorum?(agg, set)
    assert {:error, :inactive_signer} = BLS12AggSig.validate(%{agg | mask: Util.set_bit(mask, 256)}, set)
    assert {:error, :mask_nonzero_padding} = BLS12AggSig.validate(%{agg | mask: Util.set_bit(mask, 1007)}, set)
    #from the fork both sizes are derived: a stale copy is ignored, and never stored
    assert {:ok, _} = BLS12AggSig.validate(Map.merge(agg, %{mask_size: 997, mask_set_size: 1}), set)
    assert BLS12AggSig.canonical(Map.merge(agg, %{mask_size: 997, mask_set_size: 1})) == agg
  end

  test "an untrusted active mask cannot lower the quorum denominator" do
    set = %{validators: [:a, :b, :c, :d, :e], mask_active: <<0b10111000>>}
    agg = %{mask: <<0b10001000>>, mask_active: set.mask_active}
    refute BLS12AggSig.quorum?(agg, set)
    assert BLS12AggSig.score(agg) == 0.5
    assert {:error, :mask_active_mismatch} = BLS12AggSig.validate(%{agg | mask_active: agg.mask}, set)
    refute BLS12AggSig.quorum?(%{agg | mask_active: agg.mask}, set)
    assert {:error, :mask_active_mismatch} = BLS12AggSig.validate(Map.delete(agg, :mask_active), set)
    assert {:error, :mask_wrong_size} = BLS12AggSig.validate(%{agg | mask: agg.mask <> <<0>>}, set)
    agg = %{agg | mask: <<0b10011000>>}
    assert BLS12AggSig.quorum?(agg, set)
    assert BLS12AggSig.score(agg) == 0.75
    refute BLS12AggSig.quorum?(BLS12AggSig.new_padded(ValidatorSet.normalize([])))
  end

  test "aggregates retain active mask and stable indices; removed keys cannot be added" do
    keys = for _ <- 1..5 do
      seed = :crypto.strong_rand_bytes(64)
      %{seed: seed, pk: BlsEx.get_public_key!(seed)}
    end
    roster = Enum.map(keys, & &1.pk)
    set = %{validators: roster, mask_active: <<0b10111000>>}
    msg = "immutable validator slots"
    attestations = for i <- [0, 3, 4] do
      key = Enum.at(keys, i)
      %{signer: key.pk, signature: BlsEx.sign!(key.seed, msg, BLS12AggSig.dst_att())}
    end
    agg = BLS12AggSig.aggregate(set, attestations)
    assert agg.mask == <<0b10011000>>
    assert agg.mask_active == set.mask_active
    refute Map.has_key?(agg, :mask_size) or Map.has_key?(agg, :mask_set_size)
    assert {:ok, signers} = BLS12AggSig.validate(agg, set)
    assert BlsEx.verify?(BlsEx.aggregate_public_keys!(signers), agg.aggsig, msg, BLS12AggSig.dst_att())
    first = hd(attestations)
    assert BLS12AggSig.add_padded(agg, set, first.signer, first.signature) == agg
    assert catch_throw(BLS12AggSig.add_padded(agg, set, Enum.at(roster, 1), first.signature)) == %{error: :inactive_signer}
    legacy = BLS12AggSig.aggregate(roster, attestations)
    refute Map.has_key?(legacy, :mask_active)
    assert legacy.mask_size == 5 and legacy.mask_set_size == 3
    assert {:ok, ^signers} = BLS12AggSig.validate(legacy, roster)
    #a fork aggregate carries no mask_size, so a legacy roster rejects it first
    assert {:error, :mask_size_mismatch} = BLS12AggSig.validate(agg, roster)
  end
end
