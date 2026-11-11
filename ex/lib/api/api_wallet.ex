defmodule API.Wallet do
    def my_balance(symbol \\ "AMA") do
        pk = Application.fetch_env!(:ama, :trainer_pk)
        balance(pk, symbol)
    end

    #def balance(pk, symbol \\ "AMA") do
    def balance(pk, symbol \\ "AMA") do
        pk = API.maybe_b58(48, pk)
        coins = DB.Chain.balance(pk, symbol)
        %{symbol: symbol, flat: coins, float: BIC.Coin.from_flat(coins)}
    end

    def balance_all(pk) do
        pk = API.maybe_b58(48, pk)
        %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
        opts = %{db: db, cf: cf.contractstate, to_integer: true}
        RocksDB.get_prefix("account:#{pk}:balance:", opts)
        |> Enum.map(fn({symbol, coins})->
            %{symbol: symbol, flat: coins, float: BIC.Coin.from_flat(coins)}
        end)
    end

    def balance_nft(pk, collection, token) do
        pk = API.maybe_b58(48, pk)
        amount = DB.Chain.balance_nft(pk, collection, token)
        %{collection: collection, token: token, amount: amount}
    end

    def balance_nft_all(pk) do
      pk = API.maybe_b58(48, pk)
      %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
      opts = %{db: db, cf: cf.contractstate, to_integer: true}
      RocksDB.get_prefix("account:#{pk}:nft:", opts)
      |> Enum.map(fn({symbol, amount})->
          [collection, token] = :binary.split(symbol, ":")
          %{collection: collection, token: token, amount: amount}
      end)
    end

    def transfer(to, amount, symbol) do
        sk = Application.fetch_env!(:ama, :trainer_sk)
        transfer(sk, to, amount, symbol)
    end

    def transfer(from_sk, to, amount, symbol, broadcast \\ true) do
        from_sk = API.maybe_b58(64, from_sk)
        to = API.maybe_b58(48, to)
        if !BlsEx.validate_public_key(to) and to != BIC.Coin.burn_address(), do: throw(%{error: :invalid_receiver_pk})
        amount = if is_float(amount) do round(amount * 1_000_000_000) else amount end
        amount = if is_integer(amount) do :erlang.integer_to_binary(amount) else amount end
        txu = TX.build(from_sk, "Coin", "transfer", [to, amount, symbol])
        broadcast && TXPool.insert_and_broadcast(txu)
        txu
    end

    def transfer_nft(from_sk, to, amount, collection, token, broadcast \\ true) do
        from_sk = API.maybe_b58(64, from_sk)
        to = API.maybe_b58(48, to)
        if !BlsEx.validate_public_key(to) and to != BIC.Coin.burn_address(), do: throw(%{error: :invalid_receiver_pk})
        amount = :erlang.integer_to_binary(amount)
        txu = TX.build(from_sk, "Nft", "transfer", [to, amount, collection, token])
        broadcast && TXPool.insert_and_broadcast(txu)
        txu
    end

    def generate_key() do
        sk = :crypto.strong_rand_bytes(64)
        pk = BlsEx.get_public_key!(sk)
        {Base58.encode(pk), Base58.encode(sk)}
    end

    def generate_keypair() do
      sk = :crypto.strong_rand_bytes(64)
      pk = BlsEx.get_public_key!(sk)
      {Base58.encode(pk), Base58.encode(sk)}
    end
end
