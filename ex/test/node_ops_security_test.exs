defmodule NodeOpsSecurityTest do
  use ExUnit.Case, async: true

  @internal_ops [
    :new_phone_who_dis_reply_ns,
    :get_peer_anrs_reply_ns,
    :ping_reply_ns
  ]

  test "local state-transition operations are not accepted wire operations" do
    Enum.each(@internal_ops, fn op ->
      assert NodeOps.quota(op) == nil
      refute Map.has_key?(NodeOps.op_atoms(), Atom.to_string(op))
    end)
  end

  test "all rate-limited operations are wire operations" do
    Enum.each(NodeOps.quotas(), fn {op, quota} ->
      assert is_integer(quota) and quota > 0
      assert NodeOps.op_atoms()[Atom.to_string(op)] == op
    end)
  end

  test "the network decoder rejects local state-transition operations" do
    Enum.each(@internal_ops, fn op ->
      compressed = NodeProto.compress(%{op: Atom.to_string(op)})

      assert catch_throw(NodeProto.decompress_and_unpack(compressed)) ==
               %{error: :unknown_op, op: Atom.to_string(op)}
    end)
  end
end
