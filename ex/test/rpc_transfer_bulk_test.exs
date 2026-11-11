defmodule RPC.TransferBulkFromTextTest do
  use ExUnit.Case, async: true

  test "parses whitespace separated AMA amounts and skips blank lines" do
    text = "\n pk1  10\r\npk2\t0.5\n\n   \npk3 1e2\n"
    assert RPC.API.Wallet.transfer_bulk_from_text(nil, text) == [{"pk1", 10.0}, {"pk2", 0.5}, {"pk3", 100.0}]
  end

  test "rejects malformed lines" do
    for line <- ["pk1", "pk1 abc", "pk1 1,5", "pk1 0", "pk1 -1", "pk1 1 AMA"] do
      assert catch_throw(RPC.API.Wallet.transfer_bulk_from_text(nil, line)) == %{error: :invalid_line, line: line}
    end
  end
end
