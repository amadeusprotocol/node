defmodule TXAdmissionSecurityTest do
  use ExUnit.Case, async: false

  defp txu(nonce, action \\ %{op: "call", contract: "Coin", function: "transfer", args: []}) do
    tx = %{signer: :binary.copy(<<1>>, 48), nonce: nonce, action: action}

    %{
      tx: tx,
      hash: :crypto.hash(:sha256, RDB.vecpak_encode(tx)),
      signature: :binary.copy(<<0>>, 96)
    }
  end

  defp admission_args(txu, chain_nonce, balance) do
    %{
      epoch: 0,
      height: 0,
      segment_vr_hash: :binary.copy(<<0>>, 32),
      diff_bits: 24,
      batch_state: %{
        {:chain_nonce, txu.tx.signer} => chain_nonce,
        {:balance, txu.tx.signer} => balance
      }
    }
  end

  defp funded_txu(nonce) do
    TX.build(Application.fetch_env!(:ama, :trainer_sk), "", "", [], nonce)
  end

  defp fresh_nonce(offset \\ 0) do
    chain_nonce = DB.Chain.nonce(Application.fetch_env!(:ama, :trainer_pk)) || -1
    max(:os.system_time(:nanosecond), chain_nonce + 1) + offset
  end

  defp admit(txu) do
    TXPool.insert(txu, admission_args(txu, nil, 10_000_000_000))
  end

  test "structural errors are returned before signature verification" do
    assert TX.validate(txu("not-a-nonce")) == %{error: :nonce_not_integer}

    invalid_action = %{op: "call", contract: "Coin", function: "transfer", args: [123]}
    assert TX.validate(txu(100, invalid_action)) == %{error: :arg_must_be_binary}
  end

  test "normally signed transactions still pass split validation" do
    txu = TX.build(:crypto.strong_rand_bytes(64), "Coin", "transfer", [], 1_000)

    assert %{error: :ok, txu: ^txu} = TX.validate(txu)
  end

  test "global pool byte limit is two GiB" do
    assert TXPool.max_bytes() == 2 * 1024 * 1024 * 1024
  end

  test "smallest signed transaction packs to 293 bytes" do
    txu = TX.build(:crypto.strong_rand_bytes(64), "", "", [], 0)

    assert byte_size(TX.pack(txu)) == 293
  end

  test "byte reservations cannot cross their hard limit" do
    counter = :atomics.new(1, [])

    assert TXPool.reserve_bytes(counter, 7, 10)
    refute TXPool.reserve_bytes(counter, 4, 10)
    assert :atomics.get(counter, 1) == 7
    assert TXPool.release_bytes(counter, 7) == 0
  end

  test "successful insertion stores its packed size and deletion releases it" do
    txu = funded_txu(fresh_nonce())
    tx_bytes = byte_size(TX.pack(txu))
    key = {txu.tx.nonce, txu.hash}
    initial_bytes = TXPool.bytes()

    try do
      assert %{error: :ok, inserted: true, txu: ^txu} = admit(txu)
      assert TXPool.bytes() == initial_bytes + tx_bytes
      assert [{^key, ^txu, ^tx_bytes}] = :ets.lookup(TXPool, key)
      assert [{_random_key, _random_txu}] = TXPool.random(1)
      assert TXPool.lowest_nonce(txu.tx.signer) <= txu.tx.nonce
      assert {highest_nonce, count} = TXPool.highest_nonce(txu.tx.signer)
      assert highest_nonce >= txu.tx.nonce
      assert count >= 1
      assert txu in API.TXPool.get()
      assert txu in API.TXPool.get(txu.tx.signer)

      assert TXPool.purge_stale() == :ok
      assert [{^key, ^txu, ^tx_bytes}] = :ets.lookup(TXPool, key)

      assert %{error: :ok, inserted: false, txu: ^txu} = admit(txu)
      assert TXPool.bytes() == initial_bytes + tx_bytes
    after
      TXPool.delete_packed(txu)
    end

    assert :ets.lookup(TXPool, key) == []
    assert TXPool.bytes() == initial_bytes
  end

  test "invalid signatures release their byte reservation" do
    txu = funded_txu(fresh_nonce())
    invalid_txu = %{txu | signature: :binary.copy(<<0>>, 96)}
    key = {invalid_txu.tx.nonce, invalid_txu.hash}
    initial_bytes = TXPool.bytes()

    assert admit(invalid_txu) == %{error: :invalid_signature}
    assert :ets.lookup(TXPool, key) == []
    assert TXPool.bytes() == initial_bytes
  end

  test "concurrent duplicate admission stores and accounts for one transaction" do
    txu = funded_txu(fresh_nonce())
    tx_bytes = byte_size(TX.pack(txu))
    initial_bytes = TXPool.bytes()

    try do
      results =
        1..12
        |> Task.async_stream(fn _ -> admit(txu) end,
          max_concurrency: 12,
          ordered: false,
          timeout: 30_000
        )
        |> Enum.map(fn {:ok, result} -> result end)

      assert Enum.all?(results, &match?(%{error: :ok, txu: ^txu}, &1))
      assert Enum.count(results, &match?(%{inserted: true}, &1)) == 1
      assert Enum.count(results, &match?(%{inserted: false}, &1)) == 11
      assert TXPool.bytes() == initial_bytes + tx_bytes
    after
      TXPool.delete_packed(txu)
    end

    assert TXPool.bytes() == initial_bytes
  end

  test "concurrent admission cannot cross the configured byte limit" do
    txus = Enum.map(1..12, &funded_txu(fresh_nonce(&1)))
    tx_sizes = Map.new(txus, &{&1.hash, byte_size(TX.pack(&1))})
    initial_bytes = TXPool.bytes()
    previous_limit = TXPool.max_bytes()
    test_limit = initial_bytes + (tx_sizes |> Map.values() |> Enum.take(3) |> Enum.sum())

    Application.put_env(:ama, :txpool_max_bytes, test_limit)

    try do
      results =
        txus
        |> Task.async_stream(&admit/1,
          max_concurrency: length(txus),
          ordered: false,
          timeout: 30_000
        )
        |> Enum.map(fn {:ok, result} -> result end)

      inserted = for %{error: :ok, inserted: true, txu: txu} <- results, do: txu
      inserted_bytes = Enum.sum(Enum.map(inserted, &Map.fetch!(tx_sizes, &1.hash)))

      assert inserted != []
      assert Enum.any?(results, &match?(%{error: :txpool_full}, &1))
      assert TXPool.bytes() == initial_bytes + inserted_bytes
      assert TXPool.bytes() <= test_limit
    after
      TXPool.delete_packed(txus)
      Application.put_env(:ama, :txpool_max_bytes, previous_limit)
    end

    assert TXPool.bytes() == initial_bytes
  end

  test "mempool admission checks chain nonce before signature verification" do
    txu = txu(1_000)

    assert TXPool.validate_tx(txu, admission_args(txu, 1_000, 10_000_000_000)) ==
             %{error: :invalid_tx_nonce, key: {txu.tx.nonce, txu.hash}}
  end

  test "mempool admission rejects unfunded accounts before signature verification" do
    txu = txu(1_000)

    assert TXPool.validate_tx(txu, admission_args(txu, nil, 0)) ==
             %{error: :not_enough_tx_exec_balance, key: {txu.tx.nonce, txu.hash}}
  end

  test "a funded transaction with a fresh nonce reaches signature verification" do
    txu = txu(1_000)
    args = admission_args(txu, 999, 10_000_000_000)

    assert %{error: :ok} = TXPool.validate_tx(txu, args)
    assert TX.validate_signature(txu) == %{error: :invalid_signature}
  end
end
