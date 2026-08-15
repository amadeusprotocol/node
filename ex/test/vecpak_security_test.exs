defmodule VecpakSecurityTest do
  use ExUnit.Case, async: true

  test "deeply nested lists return a depth error without crashing the VM" do
    payload = :binary.copy(<<6, 1>>, 100_000) <> <<0>>

    assert RDB.vecpak_decode(payload) == :depth_limit_exceeded
  end

  test "deeply nested property lists return a depth error without crashing the VM" do
    payload = :binary.copy(<<7, 1>>, 100_000) <> :binary.copy(<<0>>, 100_001)

    assert RDB.vecpak_decode(payload) == :depth_limit_exceeded
  end

  test "ordinary vecpak input still decodes" do
    encoded = RDB.vecpak_encode([nil])

    assert RDB.vecpak_decode(encoded) == [nil]
  end
end
