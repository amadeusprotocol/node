defmodule Testnet do
  def call(sk, contract, function, args, attach_symbol \\ nil, attach_amount \\ nil) do
    txu = TX.build(sk, contract, function, args, nil, attach_symbol, attach_amount)
    API.TX.submit_and_wait(txu |> TX.pack(), false, false)
  end

  def view(contract, function, args, view_pk \\ nil) do
    API.Contract.view(contract, function, args, view_pk)
  end

  def read(key) do
    %{db: db, cf: cf} = :persistent_term.get({:rocksdb, Fabric})
    RocksDB.get(key, %{db: db, cf: cf.contractstate})
  end

  def deploy(path) do deploy(Application.fetch_env!(:ama, :keys) |> Enum.at(0), path) end
  def deploy(key, path, init_func \\ nil) do
    bytecode = File.read!(path)
    args = if init_func do [bytecode, init_func] else [bytecode] end
    gas = RDBProtocol.cost_per_new_leaf_merkle() + (RDBProtocol.cost_per_byte_state() + RDBProtocol.cost_per_byte_historical()) * byte_size(bytecode) + 10 * RDBProtocol.ama_1_cent()
    txu = TX.build(key.seed, "Contract", "deploy", args, nil, nil, nil, gas)
    API.TX.submit_and_wait(txu |> TX.pack(), false, false)
  end

  def transfer(to, amount, symbol \\ "AMA") do
    key0 = Application.fetch_env!(:ama, :keys) |> Enum.at(0)
    to = if byte_size(to) != 48, do: Base58.decode(to), else: to
    amount = if is_float(amount) do trunc(amount * 1_000_000_000) else amount end
    amount = if is_integer(amount) do :erlang.integer_to_binary(amount) else amount end
    Testnet.call(key0.seed, "Coin", "transfer", [to, amount, symbol])
  end

  def slash_trainer(signer_count \\ 1) do
    height = DB.Chain.height() + 1
    epoch = div(height, 100_000)
    set = DB.Chain.validator_set_for_height(height)
    validators = ValidatorSet.active(set)
    malicious_pk = List.last(validators)
    validators_signing = DB.Chain.validators_for_height_my(height) |> Enum.take(signer_count)

    aggsig = BLS12AggSig.new_padded(set)
    aggsig = Enum.reduce(validators_signing, aggsig, fn(signer_pk, aggsig)->
      msg = <<"slash_trainer", epoch::32-little, malicious_pk::binary>>
      seed = Application.fetch_env!(:ama, :keys_by_pk)[signer_pk].seed
      signature = BlsEx.sign!(seed, msg, BLS12AggSig.dst_motion())
      BLS12AggSig.add_padded(aggsig, set, signer_pk, signature)
    end)

    signer_sk = Application.fetch_env!(:ama, :trainer_sk)
    txu = SpecialMeetingGen.build_slash_tx(signer_sk, malicious_pk, epoch, aggsig.aggsig, aggsig.mask, length(ValidatorSet.roster(set)))
    API.TX.submit_and_wait(TX.pack(txu), false, false)
  end
end
