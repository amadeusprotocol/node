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

  defp signed_txus(count) do
    sk = :crypto.strong_rand_bytes(64)
    base_nonce = fresh_nonce()
    Enum.map(1..count, &TX.build(sk, "", "", [], base_nonce + &1))
  end

  defp fresh_nonce(offset \\ 0) do
    chain_nonce = DB.Chain.nonce(Application.fetch_env!(:ama, :trainer_pk)) || -1
    max(:os.system_time(:nanosecond), chain_nonce + 1) + offset
  end

  defp admit(txu, balance \\ 10_000_000_000) do
    TXPool.insert(txu, admission_args(txu, nil, balance))
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

  test "each pending transaction reserves 1.2 AMA" do
    assert TXPool.tx_reserve_ama() == 1_200_000_000
  end

  test "successful insertion stores its packed size and deletion releases it" do
    txu = funded_txu(fresh_nonce())
    tx_bytes = byte_size(TX.pack(txu))
    reserved_ama = TXPool.tx_reserve_ama()
    key = {txu.tx.nonce, txu.hash}
    initial_bytes = TXPool.bytes()
    initial_reservation = TXPool.signer_reservation(txu.tx.signer)

    try do
      assert %{error: :ok, inserted: true, txu: ^txu} = admit(txu)
      assert TXPool.bytes() == initial_bytes + tx_bytes
      assert [{^key, ^txu, ^tx_bytes, ^reserved_ama}] = :ets.lookup(TXPool, key)

      assert TXPool.signer_reservation(txu.tx.signer) == %{
               count: initial_reservation.count + 1,
               reserved_ama: initial_reservation.reserved_ama + reserved_ama
             }

      assert [{_random_key, _random_txu}] = TXPool.random(1)
      assert TXPool.lowest_nonce(txu.tx.signer) <= txu.tx.nonce
      assert {highest_nonce, count} = TXPool.highest_nonce(txu.tx.signer)
      assert highest_nonce >= txu.tx.nonce
      assert count >= 1
      assert txu in API.TXPool.get()
      assert txu in API.TXPool.get(txu.tx.signer)

      assert %{error: :ok, inserted: false, txu: ^txu} = admit(txu)
      assert TXPool.bytes() == initial_bytes + tx_bytes
      assert TXPool.signer_reservation(txu.tx.signer).count == initial_reservation.count + 1
    after
      TXPool.delete_packed(txu)
    end

    assert :ets.lookup(TXPool, key) == []
    assert TXPool.bytes() == initial_bytes
    assert TXPool.signer_reservation(txu.tx.signer) == initial_reservation
  end

  test "invalid signatures release their byte reservation" do
    txu = funded_txu(fresh_nonce())
    invalid_txu = %{txu | signature: :binary.copy(<<0>>, 96)}
    key = {invalid_txu.tx.nonce, invalid_txu.hash}
    initial_bytes = TXPool.bytes()
    initial_reservation = TXPool.signer_reservation(invalid_txu.tx.signer)

    assert admit(invalid_txu) == %{error: :invalid_signature}
    assert :ets.lookup(TXPool, key) == []
    assert TXPool.bytes() == initial_bytes
    assert TXPool.signer_reservation(invalid_txu.tx.signer) == initial_reservation
  end

  test "concurrent duplicate admission stores and accounts for one transaction" do
    txu = funded_txu(fresh_nonce())
    tx_bytes = byte_size(TX.pack(txu))
    reserved_ama = TXPool.tx_reserve_ama()
    initial_bytes = TXPool.bytes()
    initial_reservation = TXPool.signer_reservation(txu.tx.signer)

    try do
      results =
        1..12
        |> Task.async_stream(fn _ -> admit(txu, TXPool.tx_reserve_ama() * 100) end,
          max_concurrency: 12,
          ordered: false,
          timeout: 30_000
        )
        |> Enum.map(fn {:ok, result} -> result end)

      assert Enum.all?(results, &match?(%{error: :ok, txu: ^txu}, &1))
      assert Enum.count(results, &match?(%{inserted: true}, &1)) == 1
      assert Enum.count(results, &match?(%{inserted: false}, &1)) == 11
      assert TXPool.bytes() == initial_bytes + tx_bytes

      assert TXPool.signer_reservation(txu.tx.signer) == %{
               count: initial_reservation.count + 1,
               reserved_ama: initial_reservation.reserved_ama + reserved_ama
             }
    after
      TXPool.delete_packed(txu)
    end

    assert TXPool.bytes() == initial_bytes
    assert TXPool.signer_reservation(txu.tx.signer) == initial_reservation
  end

  test "a signer cannot accumulate more collateral than its chain balance" do
    reserved_ama = TXPool.tx_reserve_ama()
    balance = reserved_ama * 3
    txus = signed_txus(4)
    signer = hd(txus).tx.signer
    initial_reservation = TXPool.signer_reservation(signer)

    try do
      results = Enum.map(txus, &admit(&1, balance))

      assert Enum.count(results, &match?(%{error: :ok, inserted: true}, &1)) == 3

      assert %{
               error: :not_enough_txpool_balance,
               balance: ^balance,
               reserved_ama: current_reserved,
               required_ama: required_ama
             } = List.last(results)

      assert current_reserved == initial_reservation.reserved_ama + reserved_ama * 3
      assert required_ama == current_reserved + reserved_ama

      assert TXPool.signer_reservation(signer) == %{
               count: initial_reservation.count + 3,
               reserved_ama: current_reserved
             }
    after
      TXPool.delete_packed(txus)
    end

    assert TXPool.signer_reservation(signer) == initial_reservation
  end

  test "concurrent admission cannot cross a signer's collateral limit" do
    reserved_ama = TXPool.tx_reserve_ama()
    balance = reserved_ama * 4
    txus = signed_txus(16)
    signer = hd(txus).tx.signer
    initial_reservation = TXPool.signer_reservation(signer)

    try do
      results =
        txus
        |> Task.async_stream(&admit(&1, balance),
          max_concurrency: length(txus),
          ordered: false,
          timeout: 30_000
        )
        |> Enum.map(fn {:ok, result} -> result end)

      assert Enum.count(results, &match?(%{error: :ok, inserted: true}, &1)) == 4
      assert Enum.count(results, &match?(%{error: :not_enough_txpool_balance}, &1)) == 12

      assert TXPool.signer_reservation(signer) == %{
               count: initial_reservation.count + 4,
               reserved_ama: initial_reservation.reserved_ama + balance
             }
    after
      TXPool.delete_packed(txus)
    end

    assert TXPool.signer_reservation(signer) == initial_reservation
  end

  test "purging an underfunded signer releases byte and AMA reservations" do
    sk = :crypto.strong_rand_bytes(64)
    txu = TX.build(sk, "", "", [], fresh_nonce())
    key = {txu.tx.nonce, txu.hash}
    initial_bytes = TXPool.bytes()

    try do
      assert DB.Chain.balance(txu.tx.signer) == 0
      assert %{error: :ok, inserted: true} = admit(txu, TXPool.tx_reserve_ama() * 2)
      assert TXPool.signer_reservation(txu.tx.signer).count == 1

      assert TXPool.purge_stale() == :ok
      assert :ets.lookup(TXPool, key) == []
      assert TXPool.bytes() == initial_bytes
      assert TXPool.signer_reservation(txu.tx.signer) == %{count: 0, reserved_ama: 0}
    after
      TXPool.delete_packed(txu)
    end
  end

  test "purge processes at most its entry limit and resumes from its continuation" do
    assert TXPool.purge_batch_size() == 100_000

    sk = :crypto.strong_rand_bytes(64)
    base_nonce = 9_000_000_000_000_000_000
    txus = Enum.map(1..3, &TX.build(sk, "", "", [], base_nonce + &1))
    signer = hd(txus).tx.signer
    reserved_ama = TXPool.tx_reserve_ama()

    try do
      assert DB.Chain.balance(signer) == 0

      Enum.each(txus, fn txu ->
        assert %{error: :ok, inserted: true} = admit(txu, reserved_ama * length(txus))
      end)

      assert {:continue, continuation, 2} = TXPool.purge_stale(:start, 2)
      assert TXPool.signer_reservation(signer).count == 1

      remaining_nonces =
        txus
        |> Enum.filter(fn txu -> :ets.member(TXPool, {txu.tx.nonce, txu.hash}) end)
        |> Enum.map(& &1.tx.nonce)

      assert remaining_nonces == [base_nonce + 1]

      assert {:done, 1} = TXPool.purge_stale(continuation, 2)
      assert TXPool.signer_reservation(signer) == %{count: 0, reserved_ama: 0}
    after
      TXPool.delete_packed(txus)
    end
  end

  test "concurrent admission cannot cross the configured byte limit" do
    txus = signed_txus(12)
    tx_sizes = Map.new(txus, &{&1.hash, byte_size(TX.pack(&1))})
    initial_bytes = TXPool.bytes()
    previous_limit = TXPool.max_bytes()
    test_limit = initial_bytes + (tx_sizes |> Map.values() |> Enum.take(3) |> Enum.sum())

    Application.put_env(:ama, :txpool_max_bytes, test_limit)

    try do
      results =
        txus
        |> Task.async_stream(&admit(&1, TXPool.tx_reserve_ama() * 100),
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

      signer = hd(txus).tx.signer
      assert TXPool.signer_reservation(signer).count == length(inserted)

      assert TXPool.signer_reservation(signer).reserved_ama ==
               length(inserted) * TXPool.tx_reserve_ama()
    after
      TXPool.delete_packed(txus)
      Application.put_env(:ama, :txpool_max_bytes, previous_limit)
    end

    assert TXPool.bytes() == initial_bytes
  end

  test "accounting reconciliation repairs leaked bytes and signer reservations" do
    txu = funded_txu(fresh_nonce())
    fake_signer = :crypto.strong_rand_bytes(48)
    counter = :persistent_term.get({TXPool, :byte_counter})

    try do
      assert %{error: :ok, inserted: true} = admit(txu)
      :atomics.add_get(counter, 1, 123)
      :ets.insert(TXPoolAccount, {fake_signer, 7, TXPool.tx_reserve_ama() * 7})
      dead_writer = spawn(fn -> :ok end)
      monitor = Process.monitor(dead_writer)
      assert_receive {:DOWN, ^monitor, :process, ^dead_writer, _}
      :ets.insert(TXPoolAccountingWriters, {dead_writer, true})

      expected_bytes = :ets.foldl(fn {_key, _txu, tx_bytes, _reserved}, acc -> acc + tx_bytes end, 0, TXPool)
      expected_signer = :ets.foldl(fn
        {_key, pool_txu, _tx_bytes, reserved}, %{count: count, reserved_ama: amount}
            when pool_txu.tx.signer == txu.tx.signer ->
          %{count: count + 1, reserved_ama: amount + reserved}
        _, acc -> acc
      end, %{count: 0, reserved_ama: 0}, TXPool)

      assert %{bytes: ^expected_bytes} = TXPool.reconcile_accounting()
      assert TXPool.bytes() == expected_bytes
      assert TXPool.signer_reservation(txu.tx.signer) == expected_signer
      assert TXPool.signer_reservation(fake_signer) == %{count: 0, reserved_ama: 0}
      refute :ets.member(TXPoolAccountingWriters, dead_writer)
    after
      TXPool.delete_packed(txu)
      TXPool.reconcile_accounting()
    end
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
