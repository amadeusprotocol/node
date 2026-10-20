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
        amount = if is_float(amount) do trunc(amount * 1_000_000_000) else amount end
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

    def burn(amount, symbol, ref) do
        sk = Application.fetch_env!(:ama, :trainer_sk)
        burn(sk, amount, symbol, ref)
    end

    #amount is flat units; no float conversion so it matches what was minted exactly
    def burn(from_sk, amount, symbol, ref, broadcast \\ true) do
        from_sk = API.maybe_b58(64, from_sk)
        amount = if is_integer(amount) do :erlang.integer_to_binary(amount) else amount end
        txu = TX.build(from_sk, "Coin", "burn", [amount, symbol, ref])
        broadcast && TXPool.insert_and_broadcast(txu)
        txu
    end

    def burned(pk, symbol \\ "PRIME") do
        pk = API.maybe_b58(48, pk)
        flat = API.Contract.get("bic:coin:burned:#{symbol}:#{pk}", :to_integer) || 0
        %{symbol: symbol, flat: flat, float: BIC.Coin.from_flat(flat)}
    end

    def burn_record(pk, symbol, ref) do
        pk = API.maybe_b58(48, pk)
        case API.Contract.get("bic:coin:burn:#{symbol}:#{pk}:#{ref}") do
            nil -> nil
            value -> parse_burn_record(symbol, ref, value, DB.Chain.rooted_height())
        end
    end

    def burns(pk, symbol \\ "PRIME") do
        pk = API.maybe_b58(48, pk)
        rooted_height = DB.Chain.rooted_height()
        API.Contract.get_prefix("bic:coin:burn:#{symbol}:#{pk}:")
        |> Enum.map(fn({ref, value})-> parse_burn_record(symbol, ref, value, rooted_height) end)
    end

    #records are read at the tip; fulfil only once finalized, a rewind erases unrooted ones
    defp parse_burn_record(symbol, ref, value, rooted_height) do
        [amount, height, tx_hash] = :binary.split(value, ":", [:global])
        height = :erlang.binary_to_integer(height)
        finalized = is_integer(rooted_height) and height <= rooted_height
        #flat only: redemptions are matched on exact units, never floats
        %{symbol: symbol, ref: ref, flat: :erlang.binary_to_integer(amount), height: height, tx_hash: tx_hash, finalized: finalized}
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
