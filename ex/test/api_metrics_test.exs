defmodule API.MetricsTest.Source do
  def rooted_height(), do: Process.get(:rooted, 2)
  def pruned_below_height(), do: Process.get(:pruned, 0)
  def canonical_hash(height), do: Process.get({:hash, height}, "block#{height}")
  def chain_id(), do: "genesis"
  def encode(bytes), do: bytes
  def unpack(tx), do: tx
  def entry(hash), do: Process.get({:entry, hash})
  def transaction(hash), do: Process.get({:tx, hash})
end

defmodule API.MetricsTest do
  use ExUnit.Case, async: true
  alias API.MetricsTest.Source

  setup do
    Process.put({:entry, "block1"}, %{hash: "block1", header: %{height: 1, prev_hash: "block0"}, txs: [%{hash: "tx", tx: %{signer: "sender"}}]})
    Process.put({:tx, "tx"}, %{metadata: %{entry_hash: "block1"}, receipt: %{success: true}})
    :ok
  end

  test "exports the canonical rooted block without inventing UTC time" do
    assert %{error: :ok, block: block} = API.Metrics.block(1, Source)
    assert block.timestamp == nil
    assert block.timestamp_basis == :unavailable
    assert block.transactions == [%{hash: "tx", signer: "sender", success: true}]
  end

  test "rejects unrooted, pruned and missing history" do
    assert API.Metrics.block(3, Source).error == :not_finalized
    Process.put(:pruned, 2)
    assert API.Metrics.block(1, Source).error == :history_pruned
    Process.put(:pruned, 0)
    Process.put({:hash, 1}, nil)
    assert API.Metrics.block(1, Source).error == :history_missing
  end

  test "does not confuse unknown receipts or another fork with failures" do
    Process.put({:tx, "tx"}, %{metadata: %{entry_hash: "block1"}, receipt: %{}})
    assert API.Metrics.block(1, Source).error == :receipt_missing
    Process.put({:tx, "tx"}, %{metadata: %{entry_hash: "other"}, receipt: %{success: true}})
    assert API.Metrics.block(1, Source).error == :receipt_missing
  end

  test "explicit false wins over legacy ok result" do
    assert API.Metrics.receipt_success(%{success: false, result: "ok"}) == false
    assert API.Metrics.receipt_success(%{result: "ok"}) == true
    assert API.Metrics.receipt_success(%{error: "reverted"}) == false
    assert API.Metrics.receipt_success(nil) == nil
  end

  test "height parsing rejects partial and unsafe integers" do
    assert API.Metrics.parse_height("0") == {:ok, 0}
    for value <- ["-1", "1junk", "1.5", "", "9007199254740992"] do
      assert API.Metrics.parse_height(value) == {:error, :invalid_height}
    end
  end
end
